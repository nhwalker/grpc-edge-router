package io.github.nhwalker.edgerouter;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class EdgeRegistryTest {

  private final EdgeRegistry registry = new EdgeRegistry();

  @AfterEach
  void cleanup() {
    registry.shutdown();
  }

  @Test
  void putThenSnapshotExposesEdge() {
    Object session = new Object();
    registry.put("a", 40001, session);

    assertThat(registry.channel("a")).isNotNull();
    assertThat(registry.snapshot()).extracting(EdgeRegistry.EdgeInfo::clientId).containsExactly("a");
    assertThat(registry.snapshot().get(0).loopbackPort()).isEqualTo(40001);
  }

  @Test
  void removeIfSessionOnlyRemovesMatchingSession() {
    Object session1 = new Object();
    Object session2 = new Object();
    registry.put("a", 40001, session1);

    // A stale session must not evict the current edge.
    registry.removeIfSession("a", session2);
    assertThat(registry.channel("a")).isNotNull();

    registry.removeIfSession("a", session1);
    assertThat(registry.channel("a")).isNull();
  }

  @Test
  void removeIfPortOnlyRemovesMatchingPort() {
    Object session = new Object();
    registry.put("a", 40001, session);

    registry.removeIfPort("a", 49999); // stale port -> no-op
    assertThat(registry.channel("a")).isNotNull();

    registry.removeIfPort("a", 40001);
    assertThat(registry.channel("a")).isNull();
  }

  @Test
  void reconnectReplacesPortAndEmitsEvents() {
    List<String> events = new ArrayList<>();
    registry.addListenerWithSnapshot(
        new EdgeRegistry.Listener() {
          @Override
          public void onAdded(EdgeRegistry.EdgeInfo edge) {
            events.add("ADD:" + edge.loopbackPort());
          }

          @Override
          public void onRemoved(EdgeRegistry.EdgeInfo edge) {
            events.add("REMOVE:" + edge.loopbackPort());
          }
        });

    registry.put("a", 40001, new Object());
    registry.put("a", 40002, new Object()); // reconnect on a new dynamic port

    assertThat(events).containsExactly("ADD:40001", "REMOVE:40001", "ADD:40002");
    assertThat(registry.snapshot().get(0).loopbackPort()).isEqualTo(40002);
  }

  @Test
  void snapshotIsDeliveredToNewListener() {
    registry.put("a", 40001, new Object());

    List<String> events = new ArrayList<>();
    registry.addListenerWithSnapshot(
        new EdgeRegistry.Listener() {
          @Override
          public void onAdded(EdgeRegistry.EdgeInfo edge) {
            events.add("ADD:" + edge.clientId());
          }

          @Override
          public void onRemoved(EdgeRegistry.EdgeInfo edge) {
            events.add("REMOVE:" + edge.clientId());
          }
        });

    assertThat(events).containsExactly("ADD:a");
  }
}
