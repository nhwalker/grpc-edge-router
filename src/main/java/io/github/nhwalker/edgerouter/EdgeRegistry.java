package io.github.nhwalker.edgerouter;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * In-memory directory of connected edges, keyed by {@code clientId}.
 *
 * <p>For each edge it caches a loopback {@link ManagedChannel} pointed at the dynamic port that the
 * reverse SSH tunnel is bound to on this host. The gRPC passthrough proxy looks up that channel by
 * {@code clientId} to forward calls; the directory service reads snapshots and subscribes to
 * add/remove events.
 *
 * <p>This is the single-replica, in-memory model from the design: sufficient for hundreds to low
 * thousands of edges. A distributed directory + sticky routing is the seam left for HA.
 */
public final class EdgeRegistry {

  private static final Logger log = LoggerFactory.getLogger(EdgeRegistry.class);

  /** Immutable view of an edge, safe to hand to the directory service. */
  public record EdgeInfo(String clientId, int loopbackPort, long connectedAtMillis) {}

  /** Receives add/remove notifications. Callbacks are invoked while holding the registry lock, so
   * implementations must not block. */
  public interface Listener {
    void onAdded(EdgeInfo edge);

    void onRemoved(EdgeInfo edge);
  }

  private static final class Edge {
    final String clientId;
    final int loopbackPort;
    final Object sessionToken;
    final long connectedAtMillis;
    final ManagedChannel channel;

    Edge(String clientId, int loopbackPort, Object sessionToken, ManagedChannel channel) {
      this.clientId = clientId;
      this.loopbackPort = loopbackPort;
      this.sessionToken = sessionToken;
      this.connectedAtMillis = System.currentTimeMillis();
      this.channel = channel;
    }

    EdgeInfo info() {
      return new EdgeInfo(clientId, loopbackPort, connectedAtMillis);
    }
  }

  private final ConcurrentHashMap<String, Edge> edges = new ConcurrentHashMap<>();
  private final CopyOnWriteArrayList<Listener> listeners = new CopyOnWriteArrayList<>();
  private final Object lock = new Object();

  /**
   * Register (or replace) the edge for {@code clientId}, building a cached loopback channel to
   * {@code 127.0.0.1:loopbackPort}. {@code sessionToken} identifies the owning tunnel/session so a
   * late teardown of a stale tunnel cannot evict a freshly reconnected edge.
   */
  public void put(String clientId, int loopbackPort, Object sessionToken) {
    synchronized (lock) {
      Edge existing = edges.get(clientId);
      if (existing != null
          && existing.loopbackPort == loopbackPort
          && existing.sessionToken == sessionToken) {
        return; // idempotent re-report of the same tunnel
      }
      if (existing != null) {
        shutdownChannel(existing);
        edges.remove(clientId);
        notifyRemoved(existing.info());
      }
      ManagedChannel channel =
          ManagedChannelBuilder.forAddress("127.0.0.1", loopbackPort)
              .usePlaintext()
              .keepAliveTime(30, TimeUnit.SECONDS)
              .keepAliveWithoutCalls(true)
              // Edge payloads are opaque to us; do not cap message size beyond the default unless
              // operationally needed. Keep the proxy transparent.
              .maxInboundMessageSize(Integer.MAX_VALUE)
              .build();
      Edge edge = new Edge(clientId, loopbackPort, sessionToken, channel);
      edges.put(clientId, edge);
      log.info("edge connected: clientId={} loopbackPort={}", clientId, loopbackPort);
      notifyAdded(edge.info());
    }
  }

  /** Remove the edge only if it is still the one owned by {@code sessionToken}. */
  public void removeIfSession(String clientId, Object sessionToken) {
    synchronized (lock) {
      Edge existing = edges.get(clientId);
      if (existing != null && existing.sessionToken == sessionToken) {
        shutdownChannel(existing);
        edges.remove(clientId);
        log.info("edge disconnected (session closed): clientId={}", clientId);
        notifyRemoved(existing.info());
      }
    }
  }

  /** Remove the edge only if it is still bound to {@code loopbackPort} (handles stale teardowns). */
  public void removeIfPort(String clientId, int loopbackPort) {
    synchronized (lock) {
      Edge existing = edges.get(clientId);
      if (existing != null && existing.loopbackPort == loopbackPort) {
        shutdownChannel(existing);
        edges.remove(clientId);
        log.info("edge disconnected (tunnel torn down): clientId={} loopbackPort={}", clientId,
            loopbackPort);
        notifyRemoved(existing.info());
      }
    }
  }

  /** The cached loopback channel for {@code clientId}, or {@code null} if no edge is connected. */
  public ManagedChannel channel(String clientId) {
    Edge edge = edges.get(clientId);
    return edge == null ? null : edge.channel;
  }

  /** Point-in-time snapshot of connected edges. */
  public List<EdgeInfo> snapshot() {
    List<EdgeInfo> out = new ArrayList<>(edges.size());
    for (Edge e : edges.values()) {
      out.add(e.info());
    }
    return out;
  }

  /**
   * Atomically register {@code listener} and deliver the current snapshot to it as a sequence of
   * {@code onAdded} calls, so a watcher sees a consistent view with no missed or duplicated events.
   */
  public void addListenerWithSnapshot(Listener listener) {
    synchronized (lock) {
      for (Edge e : edges.values()) {
        listener.onAdded(e.info());
      }
      listeners.add(listener);
    }
  }

  public void removeListener(Listener listener) {
    listeners.remove(listener);
  }

  /** Shut down all cached channels. Intended for process shutdown. */
  public void shutdown() {
    synchronized (lock) {
      for (Edge e : edges.values()) {
        shutdownChannel(e);
      }
      edges.clear();
    }
  }

  private void notifyAdded(EdgeInfo info) {
    for (Listener l : listeners) {
      try {
        l.onAdded(info);
      } catch (RuntimeException ex) {
        log.warn("listener onAdded failed", ex);
      }
    }
  }

  private void notifyRemoved(EdgeInfo info) {
    for (Listener l : listeners) {
      try {
        l.onRemoved(info);
      } catch (RuntimeException ex) {
        log.warn("listener onRemoved failed", ex);
      }
    }
  }

  private static void shutdownChannel(Edge edge) {
    try {
      edge.channel.shutdownNow();
    } catch (RuntimeException ex) {
      log.warn("failed to shut down channel for clientId={}", edge.clientId, ex);
    }
  }
}
