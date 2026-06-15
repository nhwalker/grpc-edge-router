package io.github.nhwalker.edgerouter;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthorizedEdgesTest {

  @Test
  void programmaticAddIsLookedUpByFingerprint() throws Exception {
    KeyPair key = KeyPairGenerator.getInstance("RSA").genKeyPair();
    AuthorizedEdges edges = new AuthorizedEdges();
    edges.add("clientA", key.getPublic());

    assertThat(edges.clientIdFor(key.getPublic())).isEqualTo("clientA");

    KeyPair other = KeyPairGenerator.getInstance("RSA").genKeyPair();
    assertThat(edges.clientIdFor(other.getPublic())).isNull();
  }

  @Test
  void fileIsParsedIntoClientIdMapping(@TempDir Path dir) throws Exception {
    KeyPair keyA = KeyPairGenerator.getInstance("RSA").genKeyPair();
    KeyPair keyB = KeyPairGenerator.getInstance("RSA").genKeyPair();

    Path file = dir.resolve("authorized_edges");
    Files.writeString(
        file,
        "# edges\n"
            + "clientA " + PublicKeyEntry.toString(keyA.getPublic()) + "\n"
            + "\n"
            + "clientB " + PublicKeyEntry.toString(keyB.getPublic()) + "\n");

    AuthorizedEdges edges = AuthorizedEdges.fromFile(file);

    assertThat(edges.size()).isEqualTo(2);
    assertThat(edges.clientIdFor(keyA.getPublic())).isEqualTo("clientA");
    assertThat(edges.clientIdFor(keyB.getPublic())).isEqualTo("clientB");
  }
}
