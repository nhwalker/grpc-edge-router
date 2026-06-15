package io.github.nhwalker.edgerouter;

import io.github.nhwalker.edgerouter.proto.Client;
import io.github.nhwalker.edgerouter.proto.ClientDirectoryGrpc;
import io.github.nhwalker.edgerouter.proto.ClientEvent;
import io.github.nhwalker.edgerouter.proto.ListClientsRequest;
import io.github.nhwalker.edgerouter.proto.ListClientsResponse;
import io.github.nhwalker.edgerouter.proto.WatchRequest;
import io.grpc.stub.ServerCallStreamObserver;
import io.grpc.stub.StreamObserver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * gRPC implementation of the gateway's {@code ClientDirectory} control-plane API. Reads snapshots
 * and live add/remove events from the {@link EdgeRegistry}.
 */
public final class DirectoryService extends ClientDirectoryGrpc.ClientDirectoryImplBase {

  private static final Logger log = LoggerFactory.getLogger(DirectoryService.class);

  private final EdgeRegistry registry;

  public DirectoryService(EdgeRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void listClients(ListClientsRequest request, StreamObserver<ListClientsResponse> responseObserver) {
    ListClientsResponse.Builder resp = ListClientsResponse.newBuilder();
    for (EdgeRegistry.EdgeInfo edge : registry.snapshot()) {
      resp.addClients(toProto(edge));
    }
    responseObserver.onNext(resp.build());
    responseObserver.onCompleted();
  }

  @Override
  public void watchClients(WatchRequest request, StreamObserver<ClientEvent> responseObserver) {
    ServerCallStreamObserver<ClientEvent> stream =
        (ServerCallStreamObserver<ClientEvent>) responseObserver;

    EdgeRegistry.Listener listener =
        new EdgeRegistry.Listener() {
          @Override
          public void onAdded(EdgeRegistry.EdgeInfo edge) {
            emit(stream, ClientEvent.Type.ADDED, edge);
          }

          @Override
          public void onRemoved(EdgeRegistry.EdgeInfo edge) {
            emit(stream, ClientEvent.Type.REMOVED, edge);
          }
        };

    stream.setOnCancelHandler(() -> registry.removeListener(listener));
    // Atomically deliver the current snapshot then subscribe to live events.
    registry.addListenerWithSnapshot(listener);
  }

  private void emit(
      ServerCallStreamObserver<ClientEvent> stream,
      ClientEvent.Type type,
      EdgeRegistry.EdgeInfo edge) {
    if (stream.isCancelled()) {
      return;
    }
    try {
      synchronized (stream) {
        stream.onNext(
            ClientEvent.newBuilder().setType(type).setClient(toProto(edge)).build());
      }
    } catch (RuntimeException ex) {
      log.debug("failed to emit watch event (stream likely closed): {}", ex.toString());
    }
  }

  private static Client toProto(EdgeRegistry.EdgeInfo edge) {
    return Client.newBuilder()
        .setId(edge.clientId())
        .setConnectedAt(edge.connectedAtMillis())
        .setOnline(true)
        .build();
  }
}
