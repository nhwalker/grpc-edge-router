package io.github.nhwalker.edgerouter;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import org.apache.sshd.common.AttributeRepository.AttributeKey;
import org.apache.sshd.common.forward.DefaultForwarder;
import org.apache.sshd.common.forward.PortForwardingEventListener;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.net.SshdSocketAddress;
import org.apache.sshd.core.CoreModuleProperties;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.forward.ForwardingFilter;
import org.apache.sshd.server.forward.TcpForwardingFilter;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Embedded SSH server that terminates edges' reverse tunnels.
 *
 * <ul>
 *   <li>Authenticates edges by public key, mapping each key to a {@code clientId} via
 *       {@link AuthorizedEdges}; unknown keys are rejected.
 *   <li>Allows only remote (reverse, {@code -R}) forwarding bound to loopback; rejects local
 *       forwarding, agent, and X11.
 *   <li>Captures the dynamically-assigned bound port from
 *       {@link PortForwardingEventListener#establishedExplicitTunnel} and registers
 *       {@code clientId -> port} in the {@link EdgeRegistry}.
 *   <li>Evicts the registry entry when the tunnel is torn down or the session closes.
 * </ul>
 */
public final class SshIngress {

  private static final Logger log = LoggerFactory.getLogger(SshIngress.class);

  /** Session attribute carrying the authenticated edge's clientId. */
  static final AttributeKey<String> CLIENT_ID = new AttributeKey<>();

  private final SshServer sshd;
  private final EdgeRegistry registry;

  public SshIngress(
      String host, int port, Path hostKeyPath, AuthorizedEdges authorizedEdges, EdgeRegistry registry) {
    this.registry = registry;
    this.sshd = SshServer.setUpDefaultServer();
    sshd.setHost(host);
    sshd.setPort(port);
    sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(hostKeyPath));

    // Public-key auth -> clientId. Reject anything not in the authorized set.
    sshd.setPublickeyAuthenticator(
        (username, key, session) -> {
          String clientId = authorizedEdges.clientIdFor(key);
          if (clientId == null) {
            log.warn("rejected SSH auth: unknown public key (username={})", username);
            return false;
          }
          session.setAttribute(CLIENT_ID, clientId);
          return true;
        });

    // Reverse-forward only. No shell, no command, no local forward, no agent/X11.
    sshd.setForwardingFilter(new LoopbackRemoteForwardingFilter());
    // Force every reverse forward to bind to loopback, so forwarded edge ports are never exposed on
    // an external interface even if the client requests a wildcard bind address.
    sshd.setForwarderFactory(LoopbackForwarder::new);

    // Generous idle timeout; edges keep the tunnel alive with SSH keepalives well under this.
    CoreModuleProperties.IDLE_TIMEOUT.set(sshd, Duration.ofMinutes(10));

    sshd.addPortForwardingEventListener(new ForwardCapture());
    sshd.addSessionListener(new CleanupOnClose());
  }

  public void start() throws IOException {
    sshd.start();
    log.info("SSH ingress listening on {}:{}", sshd.getHost(), sshd.getPort());
  }

  public void stop() throws IOException {
    sshd.stop();
  }

  /** Actual bound port (useful when constructed with port 0 in tests). */
  public int getPort() {
    return sshd.getPort();
  }

  private static String clientIdOf(Session session) {
    return session.getAttribute(CLIENT_ID);
  }

  private final class ForwardCapture implements PortForwardingEventListener {
    @Override
    public void establishedExplicitTunnel(
        Session session,
        SshdSocketAddress local,
        SshdSocketAddress remote,
        boolean localForwarding,
        SshdSocketAddress boundAddress,
        Throwable reason) {
      // The SSH server only permits reverse forwarding (canConnect == false blocks -L), so any
      // established tunnel here is an edge's reverse forward. MINA reports the server-side bind with
      // localForwarding == true, so we deliberately do not filter on that flag.
      if (reason != null || boundAddress == null) {
        return;
      }
      String clientId = clientIdOf(session);
      if (clientId == null) {
        return;
      }
      log.info("reverse tunnel established: clientId={} boundAddress={}", clientId, boundAddress);
      registry.put(clientId, boundAddress.getPort(), session);
    }

    @Override
    public void tornDownExplicitTunnel(
        Session session,
        SshdSocketAddress address,
        boolean localForwarding,
        SshdSocketAddress remoteAddress,
        Throwable reason) {
      if (address == null) {
        return;
      }
      String clientId = clientIdOf(session);
      if (clientId != null) {
        registry.removeIfPort(clientId, address.getPort());
      }
    }
  }

  private final class CleanupOnClose implements SessionListener {
    @Override
    public void sessionClosed(Session session) {
      String clientId = clientIdOf(session);
      if (clientId != null) {
        registry.removeIfSession(clientId, session);
      }
    }
  }

  /** Binds all reverse forwards to loopback, ignoring the client-requested bind address. */
  private static final class LoopbackForwarder extends DefaultForwarder {
    LoopbackForwarder(ConnectionService service) {
      super(service);
    }

    @Override
    public synchronized SshdSocketAddress localPortForwardingRequested(SshdSocketAddress local)
        throws java.io.IOException {
      SshdSocketAddress loopback = new SshdSocketAddress("127.0.0.1", local.getPort());
      return super.localPortForwardingRequested(loopback);
    }
  }

  /** Allows only loopback-bound reverse forwarding; denies everything else. */
  private static final class LoopbackRemoteForwardingFilter implements ForwardingFilter {
    @Override
    public boolean canListen(SshdSocketAddress address, Session session) {
      boolean ok = isLoopbackBind(address);
      if (!ok) {
        log.warn("denied non-loopback reverse-forward bind request: {}", address);
      }
      return ok;
    }

    @Override
    public boolean canConnect(TcpForwardingFilter.Type type, SshdSocketAddress address, Session session) {
      // No local (-L) / direct-tcpip forwarding.
      return false;
    }

    @Override
    public boolean canForwardAgent(Session session, String requestType) {
      return false;
    }

    @Override
    public boolean canForwardX11(Session session, String requestType) {
      return false;
    }

    private static boolean isLoopbackBind(SshdSocketAddress address) {
      if (address == null) {
        return true;
      }
      String host = address.getHostName();
      if (host == null || host.isEmpty()) {
        return true; // standard `-R 0:...` sends an empty bind address
      }
      // Accept the wildcard requests that a normal `-R` produces; the server is configured to bind
      // these to loopback (see SshIngress construction).
      return host.equals("localhost")
          || host.startsWith("127.")
          || host.equals("::1")
          || host.equals("0.0.0.0")
          || host.equals("::");
    }
  }
}
