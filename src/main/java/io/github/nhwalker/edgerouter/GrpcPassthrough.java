package io.github.nhwalker.edgerouter;

import io.grpc.CallOptions;
import io.grpc.ClientCall;
import io.grpc.HandlerRegistry;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.MethodDescriptor.MethodType;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerMethodDefinition;
import io.grpc.Status;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A generic, proto-agnostic gRPC proxy.
 *
 * <p>It accepts <em>any</em> method via a {@link HandlerRegistry fallback handler registry}, treats
 * request and response messages as opaque {@link InputStream}s (an identity marshaller that never
 * parses), reads the routing key from the {@code x-client-id} metadata header, and bridges the
 * inbound {@link ServerCall} to an outbound {@link ClientCall} on the edge's loopback channel.
 *
 * <p>A single stream-to-stream bridge covers all four RPC cardinalities (unary is just a stream of
 * one). Status, trailers, headers, deadlines (via gRPC {@code Context} propagation) and flow
 * control are all forwarded with fidelity — the reason the data path is Java rather than Python.
 */
public final class GrpcPassthrough {

  private static final Logger log = LoggerFactory.getLogger(GrpcPassthrough.class);

  static final Metadata.Key<String> CLIENT_ID_KEY =
      Metadata.Key.of("x-client-id", Metadata.ASCII_STRING_MARSHALLER);

  /**
   * Opaque pass-through marshaller. It never interprets the protobuf payload.
   *
   * <p>{@code parse} copies the inbound message into a self-contained buffer. This is required, not
   * just tidy: the inbound {@code InputStream} is backed by a transport network buffer that is only
   * valid during the synchronous receive callback, whereas the outbound call may buffer the message
   * (e.g. while the loopback channel is still connecting) and serialize it later on another thread.
   * Detaching the bytes makes the message safe to forward asynchronously.
   */
  private static final MethodDescriptor.Marshaller<InputStream> IDENTITY_MARSHALLER =
      new MethodDescriptor.Marshaller<>() {
        @Override
        public InputStream stream(InputStream value) {
          return value;
        }

        @Override
        public InputStream parse(InputStream stream) {
          try {
            return new ByteArrayInputStream(stream.readAllBytes());
          } catch (IOException e) {
            throw Status.INTERNAL
                .withDescription("failed to buffer proxied message")
                .withCause(e)
                .asRuntimeException();
          }
        }
      };

  private final EdgeRegistry registry;
  private final HandlerRegistry fallbackRegistry = new FallbackRegistry();

  public GrpcPassthrough(EdgeRegistry registry) {
    this.registry = registry;
  }

  /** Use with {@code ServerBuilder.fallbackHandlerRegistry(...)}. */
  public HandlerRegistry fallbackHandlerRegistry() {
    return fallbackRegistry;
  }

  private final class FallbackRegistry extends HandlerRegistry {
    @Override
    public ServerMethodDefinition<?, ?> lookupMethod(String methodName, String authority) {
      MethodDescriptor<InputStream, InputStream> method =
          MethodDescriptor.<InputStream, InputStream>newBuilder()
              .setType(MethodType.UNKNOWN)
              .setFullMethodName(methodName)
              .setRequestMarshaller(IDENTITY_MARSHALLER)
              .setResponseMarshaller(IDENTITY_MARSHALLER)
              .build();
      return ServerMethodDefinition.create(method, new PassthroughHandler());
    }
  }

  private final class PassthroughHandler
      implements ServerCallHandler<InputStream, InputStream> {
    @Override
    public ServerCall.Listener<InputStream> startCall(
        ServerCall<InputStream, InputStream> serverCall, Metadata headers) {
      String clientId = headers.get(CLIENT_ID_KEY);
      if (clientId == null || clientId.isEmpty()) {
        serverCall.close(
            Status.INVALID_ARGUMENT.withDescription("missing required x-client-id metadata"),
            new Metadata());
        return new ServerCall.Listener<>() {};
      }
      ManagedChannel channel = registry.channel(clientId);
      if (channel == null) {
        serverCall.close(
            Status.UNAVAILABLE.withDescription("no connected edge for client-id '" + clientId + "'"),
            new Metadata());
        return new ServerCall.Listener<>() {};
      }

      // Inherit the caller's deadline (and cancellation) via the current gRPC Context, which the
      // server runtime has already populated for this call.
      ClientCall<InputStream, InputStream> clientCall =
          channel.newCall(serverCall.getMethodDescriptor(), CallOptions.DEFAULT);

      CallBridge bridge = new CallBridge(serverCall, clientCall);
      // Forward the original headers verbatim (including x-client-id; harmless to the edge).
      clientCall.start(bridge.clientListener, headers);
      // Prime both directions of flow control.
      clientCall.request(1);
      serverCall.request(1);
      return bridge.serverListener;
    }
  }

  /**
   * Bridges an inbound {@link ServerCall} (the caller) and an outbound {@link ClientCall} (the
   * edge), wiring messages, half-close, cancellation, headers, trailers/status, and flow control in
   * both directions.
   */
  private static final class CallBridge {
    final ServerToClient serverListener;
    final ClientToServer clientListener;

    CallBridge(
        ServerCall<InputStream, InputStream> serverCall,
        ClientCall<InputStream, InputStream> clientCall) {
      this.serverListener = new ServerToClient(serverCall, clientCall);
      this.clientListener = new ClientToServer(serverCall, clientCall);
      serverListener.peer = clientListener;
      clientListener.peer = serverListener;
    }

    /** caller -> edge: forwards request messages and lifecycle to the {@link ClientCall}. */
    private static final class ServerToClient extends ServerCall.Listener<InputStream> {
      private final ServerCall<InputStream, InputStream> serverCall;
      private final ClientCall<InputStream, InputStream> clientCall;
      ClientToServer peer;
      private boolean needToRequest; // guarded by this

      ServerToClient(
          ServerCall<InputStream, InputStream> serverCall,
          ClientCall<InputStream, InputStream> clientCall) {
        this.serverCall = serverCall;
        this.clientCall = clientCall;
      }

      @Override
      public void onMessage(InputStream message) {
        clientCall.sendMessage(message);
        // Request the next caller message only if the edge is ready to receive it; otherwise pause
        // until the ClientCall signals readiness.
        synchronized (this) {
          if (clientCall.isReady()) {
            serverCall.request(1);
          } else {
            needToRequest = true;
          }
        }
      }

      @Override
      public void onHalfClose() {
        clientCall.halfClose();
      }

      @Override
      public void onCancel() {
        clientCall.cancel("cancelled by caller", null);
      }

      /** The serverCall is ready to send responses -> let the edge produce more (edge->caller). */
      @Override
      public void onReady() {
        peer.onServerReady();
      }

      /** Called when the edge ClientCall becomes ready to receive more request messages. */
      synchronized void onClientReady() {
        if (needToRequest) {
          serverCall.request(1);
          needToRequest = false;
        }
      }
    }

    /** edge -> caller: forwards response headers, messages, and trailers/status to the caller. */
    private static final class ClientToServer extends ClientCall.Listener<InputStream> {
      private final ServerCall<InputStream, InputStream> serverCall;
      private final ClientCall<InputStream, InputStream> clientCall;
      ServerToClient peer;
      private boolean needToRequest; // guarded by this

      ClientToServer(
          ServerCall<InputStream, InputStream> serverCall,
          ClientCall<InputStream, InputStream> clientCall) {
        this.serverCall = serverCall;
        this.clientCall = clientCall;
      }

      @Override
      public void onHeaders(Metadata headers) {
        serverCall.sendHeaders(headers);
      }

      @Override
      public void onMessage(InputStream message) {
        serverCall.sendMessage(message);
        synchronized (this) {
          if (serverCall.isReady()) {
            clientCall.request(1);
          } else {
            needToRequest = true;
          }
        }
      }

      @Override
      public void onClose(Status status, Metadata trailers) {
        serverCall.close(status, trailers);
      }

      /** The edge ClientCall is ready to send requests -> let the caller produce more. */
      @Override
      public void onReady() {
        peer.onClientReady();
      }

      /** Called when the caller ServerCall becomes ready to receive more response messages. */
      synchronized void onServerReady() {
        if (needToRequest) {
          clientCall.request(1);
          needToRequest = false;
        }
      }
    }
  }
}
