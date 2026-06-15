package io.github.nhwalker.edgerouter;

import io.grpc.Server;
import io.grpc.ServerBuilder;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Entry point. Wires the SSH ingress, the gRPC passthrough proxy, and the directory service over a
 * single shared {@link EdgeRegistry}.
 *
 * <p>Configuration via environment variables (all optional):
 *
 * <pre>
 *   GRPC_PORT              gRPC proxy + directory port (default 50000)
 *   SSH_HOST              SSH bind host (default 0.0.0.0)
 *   SSH_PORT              SSH ingress port (default 2222)
 *   HOST_KEY_PATH        SSH host key file (default data/ssh_host_key.ser)
 *   AUTHORIZED_EDGES_PATH  edge public-key -> clientId file (default config/authorized_edges)
 * </pre>
 */
public final class Main {

  private static final Logger log = LoggerFactory.getLogger(Main.class);

  public static void main(String[] args) throws Exception {
    int grpcPort = envInt("GRPC_PORT", 50000);
    String sshHost = env("SSH_HOST", "0.0.0.0");
    int sshPort = envInt("SSH_PORT", 2222);
    Path hostKeyPath = Path.of(env("HOST_KEY_PATH", "data/ssh_host_key.ser"));
    Path authorizedEdgesPath = Path.of(env("AUTHORIZED_EDGES_PATH", "config/authorized_edges"));

    Files.createDirectories(hostKeyPath.toAbsolutePath().getParent());

    AuthorizedEdges authorizedEdges;
    if (Files.exists(authorizedEdgesPath)) {
      authorizedEdges = AuthorizedEdges.fromFile(authorizedEdgesPath);
    } else {
      authorizedEdges = new AuthorizedEdges();
      log.warn(
          "no authorized edges file at {} — all SSH auth will be rejected until edges are provisioned",
          authorizedEdgesPath);
    }

    EdgeRegistry registry = new EdgeRegistry();

    SshIngress ssh = new SshIngress(sshHost, sshPort, hostKeyPath, authorizedEdges, registry);

    GrpcPassthrough passthrough = new GrpcPassthrough(registry);
    Server grpc =
        ServerBuilder.forPort(grpcPort)
            .addService(new DirectoryService(registry))
            .fallbackHandlerRegistry(passthrough.fallbackHandlerRegistry())
            .permitKeepAliveTime(15, TimeUnit.SECONDS)
            .permitKeepAliveWithoutCalls(true)
            .maxInboundMessageSize(Integer.MAX_VALUE)
            .build();

    ssh.start();
    grpc.start();
    log.info("gRPC proxy + directory listening on :{}", grpcPort);

    Runtime.getRuntime()
        .addShutdownHook(
            new Thread(
                () -> {
                  log.info("shutting down...");
                  try {
                    grpc.shutdown().awaitTermination(10, TimeUnit.SECONDS);
                  } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                  }
                  try {
                    ssh.stop();
                  } catch (IOException e) {
                    log.warn("error stopping SSH ingress", e);
                  }
                  registry.shutdown();
                },
                "shutdown"));

    grpc.awaitTermination();
  }

  private static String env(String name, String def) {
    String v = System.getenv(name);
    return v == null || v.isEmpty() ? def : v;
  }

  private static int envInt(String name, int def) {
    String v = System.getenv(name);
    return v == null || v.isEmpty() ? def : Integer.parseInt(v);
  }

  private Main() {}
}
