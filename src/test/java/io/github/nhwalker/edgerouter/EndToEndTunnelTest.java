package io.github.nhwalker.edgerouter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.nhwalker.edgerouter.proto.Client;
import io.github.nhwalker.edgerouter.proto.ClientDirectoryGrpc;
import io.github.nhwalker.edgerouter.proto.ListClientsRequest;
import io.github.nhwalker.edgerouter.proto.ListClientsResponse;
import io.github.nhwalker.edgerouter.test.EchoReply;
import io.github.nhwalker.edgerouter.test.EchoRequest;
import io.github.nhwalker.edgerouter.test.EchoServiceGrpc;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.ForwardingClientCall;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.helpers.AbstractFactoryManager;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

/**
 * Full end-to-end test: a loopback "edge" gRPC server is reverse-tunneled into the gateway over
 * SSH, and a caller drives it through the gateway's generic passthrough using {@code x-client-id}.
 * The gateway has no knowledge of the echo proto.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class EndToEndTunnelTest {

  private static final String CLIENT_ID = "clientA";

  private Server edgeServer;
  private EdgeRegistry registry;
  private SshIngress ssh;
  private Server gateway;
  private SshClient sshClient;
  private ClientSession sshSession;
  private ManagedChannel callerChannel;
  private Path hostKeyPath;
  private KeyPair caKey;

  @BeforeAll
  void setUp() throws Exception {
    // 1. The edge's local gRPC server (the thing we tunnel to).
    edgeServer = ServerBuilder.forPort(0).addService(new EchoImpl()).build().start();
    int edgePort = edgeServer.getPort();

    // 2. The edge's identity: a user certificate (principal = CLIENT_ID) signed by a trusted CA.
    caKey = KeyPairGenerator.getInstance("RSA").genKeyPair();
    KeyPair edgeKey = KeyPairGenerator.getInstance("RSA").genKeyPair();
    OpenSshCertificate edgeCert = mintUserCert(edgeKey, caKey, CLIENT_ID);

    CertificateAuthorities cas = new CertificateAuthorities();
    cas.addTrustedCa(caKey.getPublic());

    // 3. The gateway: SSH ingress + gRPC proxy/directory over one registry.
    registry = new EdgeRegistry();
    hostKeyPath = Files.createTempFile("edge-router-hostkey", ".ser");
    Files.deleteIfExists(hostKeyPath); // let MINA generate it
    ssh = new SshIngress("127.0.0.1", 0, hostKeyPath, cas, registry);
    ssh.start();

    GrpcPassthrough passthrough = new GrpcPassthrough(registry);
    gateway =
        ServerBuilder.forPort(0)
            .addService(new DirectoryService(registry))
            .fallbackHandlerRegistry(passthrough.fallbackHandlerRegistry())
            .build()
            .start();

    // 4. The edge dials out: authenticate with the cert, then reverse-forward localhost:edgePort.
    sshClient = SshClient.setUpDefaultClient();
    sshClient.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
    enableCertSignatures(sshClient);
    sshClient.start();
    sshSession =
        sshClient.connect(CLIENT_ID, "127.0.0.1", ssh.getPort()).verify(5000).getSession();
    sshSession.addPublicKeyIdentity(new KeyPair(edgeCert, edgeKey.getPrivate()));
    sshSession.auth().verify(5000);
    sshSession.startRemotePortForwarding(
        new SshdSocketAddress("", 0), new SshdSocketAddress("localhost", edgePort));

    // Wait for the server-side forwarding event to register the edge.
    awaitEdgeRegistered();

    // 5. The caller's channel to the gateway, injecting x-client-id on every call.
    callerChannel =
        ManagedChannelBuilder.forAddress("127.0.0.1", gateway.getPort())
            .usePlaintext()
            .intercept(clientIdInterceptor(CLIENT_ID))
            .build();
  }

  @AfterAll
  void tearDown() throws Exception {
    if (callerChannel != null) {
      callerChannel.shutdownNow();
    }
    if (sshSession != null) {
      sshSession.close(false);
    }
    if (sshClient != null) {
      sshClient.stop();
    }
    if (gateway != null) {
      gateway.shutdownNow();
    }
    if (ssh != null) {
      ssh.stop();
    }
    if (registry != null) {
      registry.shutdown();
    }
    if (edgeServer != null) {
      edgeServer.shutdownNow();
    }
    if (hostKeyPath != null) {
      Files.deleteIfExists(hostKeyPath);
    }
  }

  @Test
  void unaryCallIsProxiedThroughTunnel() {
    EchoServiceGrpc.EchoServiceBlockingStub stub = EchoServiceGrpc.newBlockingStub(callerChannel);
    EchoReply reply = stub.echo(EchoRequest.newBuilder().setMessage("hello").build());
    assertThat(reply.getMessage()).isEqualTo("echo: hello");
  }

  @Test
  void serverStreamingIsProxiedThroughTunnel() {
    EchoServiceGrpc.EchoServiceBlockingStub stub = EchoServiceGrpc.newBlockingStub(callerChannel);
    Iterator<EchoReply> it =
        stub.echoStream(EchoRequest.newBuilder().setMessage("x").setCount(3).build());
    List<String> got = new ArrayList<>();
    while (it.hasNext()) {
      got.add(it.next().getMessage());
    }
    assertThat(got).containsExactly("echo[0]: x", "echo[1]: x", "echo[2]: x");
  }

  @Test
  void directoryListsTheConnectedEdge() {
    ClientDirectoryGrpc.ClientDirectoryBlockingStub stub =
        ClientDirectoryGrpc.newBlockingStub(callerChannel);
    ListClientsResponse resp = stub.listClients(ListClientsRequest.getDefaultInstance());
    assertThat(resp.getClientsList().stream().map(Client::getId)).contains(CLIENT_ID);
    assertThat(resp.getClientsList().stream().anyMatch(Client::getOnline)).isTrue();
  }

  @Test
  void unknownClientIdIsUnavailable() {
    ManagedChannel ghost =
        ManagedChannelBuilder.forAddress("127.0.0.1", gateway.getPort())
            .usePlaintext()
            .intercept(clientIdInterceptor("ghost"))
            .build();
    try {
      EchoServiceGrpc.EchoServiceBlockingStub stub = EchoServiceGrpc.newBlockingStub(ghost);
      assertThatThrownBy(() -> stub.echo(EchoRequest.newBuilder().setMessage("hi").build()))
          .isInstanceOf(StatusRuntimeException.class)
          .hasMessageContaining("UNAVAILABLE");
    } finally {
      ghost.shutdownNow();
    }
  }

  @Test
  void missingClientIdIsRejected() {
    ManagedChannel noHeader =
        ManagedChannelBuilder.forAddress("127.0.0.1", gateway.getPort()).usePlaintext().build();
    try {
      EchoServiceGrpc.EchoServiceBlockingStub stub = EchoServiceGrpc.newBlockingStub(noHeader);
      assertThatThrownBy(() -> stub.echo(EchoRequest.newBuilder().setMessage("hi").build()))
          .isInstanceOf(StatusRuntimeException.class)
          .hasMessageContaining("INVALID_ARGUMENT");
    } finally {
      noHeader.shutdownNow();
    }
  }

  @Test
  void untrustedCaCertIsRejectedAtAuth() throws Exception {
    // A cert for the right principal but signed by a CA the gateway does not trust must not auth.
    KeyPair untrustedCa = KeyPairGenerator.getInstance("RSA").genKeyPair();
    KeyPair edgeKey = KeyPairGenerator.getInstance("RSA").genKeyPair();
    OpenSshCertificate cert = mintUserCert(edgeKey, untrustedCa, CLIENT_ID);

    SshClient client = SshClient.setUpDefaultClient();
    enableCertSignatures(client);
    client.start();
    try (ClientSession session =
        client.connect(CLIENT_ID, "127.0.0.1", ssh.getPort()).verify(5000).getSession()) {
      session.addPublicKeyIdentity(new KeyPair(cert, edgeKey.getPrivate()));
      assertThatThrownBy(() -> session.auth().verify(5000)).isInstanceOf(Exception.class);
    } finally {
      client.stop();
    }
  }

  private static OpenSshCertificate mintUserCert(KeyPair subject, KeyPair ca, String... principals)
      throws Exception {
    return OpenSshCertificateBuilder.userCertificate()
        .publicKey(subject.getPublic())
        .id("edge-" + String.join(",", principals))
        .principals(List.of(principals))
        .validAfter(Instant.now().minusSeconds(60))
        .validBefore(Instant.now().plusSeconds(3600))
        .sign(ca);
  }

  /** Advertise the OpenSSH certificate signature algorithms on a client/server factory manager. */
  private static void enableCertSignatures(AbstractFactoryManager mgr) {
    List<NamedFactory<Signature>> factories = new ArrayList<>(mgr.getSignatureFactories());
    for (BuiltinSignatures cert :
        List.of(
            BuiltinSignatures.ed25519_cert,
            BuiltinSignatures.rsaSHA512_cert,
            BuiltinSignatures.rsaSHA256_cert,
            BuiltinSignatures.nistp256_cert,
            BuiltinSignatures.nistp384_cert,
            BuiltinSignatures.nistp521_cert)) {
      if (cert.isSupported() && !factories.contains(cert)) {
        factories.add(cert);
      }
    }
    mgr.setSignatureFactories(factories);
  }

  private void awaitEdgeRegistered() throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (System.nanoTime() < deadline) {
      if (registry.channel(CLIENT_ID) != null) {
        return;
      }
      Thread.sleep(25);
    }
    throw new AssertionError("edge was not registered within timeout");
  }

  private static ClientInterceptor clientIdInterceptor(String clientId) {
    return new ClientInterceptor() {
      @Override
      public <Q, A> ClientCall<Q, A> interceptCall(
          MethodDescriptor<Q, A> method, CallOptions callOptions, Channel next) {
        return new ForwardingClientCall.SimpleForwardingClientCall<>(next.newCall(method, callOptions)) {
          @Override
          public void start(Listener<A> responseListener, Metadata headers) {
            headers.put(GrpcPassthrough.CLIENT_ID_KEY, clientId);
            super.start(responseListener, headers);
          }
        };
      }
    };
  }

  private static final class EchoImpl extends EchoServiceGrpc.EchoServiceImplBase {
    @Override
    public void echo(EchoRequest request, StreamObserver<EchoReply> responseObserver) {
      responseObserver.onNext(EchoReply.newBuilder().setMessage("echo: " + request.getMessage()).build());
      responseObserver.onCompleted();
    }

    @Override
    public void echoStream(EchoRequest request, StreamObserver<EchoReply> responseObserver) {
      int n = request.getCount() <= 0 ? 1 : request.getCount();
      for (int i = 0; i < n; i++) {
        responseObserver.onNext(
            EchoReply.newBuilder().setMessage("echo[" + i + "]: " + request.getMessage()).build());
      }
      responseObserver.onCompleted();
    }
  }
}
