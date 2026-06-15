package io.github.nhwalker.edgerouter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Maps an edge's SSH public key to its {@code clientId}. This is the identity and revocation point
 * for edges: a key not present here cannot authenticate.
 *
 * <p>Backed by a simple text file, one entry per line:
 *
 * <pre>
 *   # comment
 *   clientA ssh-ed25519 AAAAC3Nza... optional-comment
 *   clientB ssh-rsa AAAAB3Nza...
 * </pre>
 *
 * i.e. an OpenSSH {@code authorized_keys} line prefixed with the clientId. Keys are matched by
 * SHA-256 fingerprint.
 */
public final class AuthorizedEdges {

  private static final Logger log = LoggerFactory.getLogger(AuthorizedEdges.class);

  // fingerprint -> clientId
  private final Map<String, String> byFingerprint = new ConcurrentHashMap<>();

  /** Register a key programmatically (used in tests and for in-memory provisioning). */
  public void add(String clientId, PublicKey key) {
    byFingerprint.put(KeyUtils.getFingerPrint(key), clientId);
  }

  /** The clientId for {@code key}, or {@code null} if the key is not authorized. */
  public String clientIdFor(PublicKey key) {
    return byFingerprint.get(KeyUtils.getFingerPrint(key));
  }

  public int size() {
    return byFingerprint.size();
  }

  /** Load entries from a file. Lines that are blank or start with {@code #} are ignored. */
  public static AuthorizedEdges fromFile(Path path) throws IOException {
    AuthorizedEdges edges = new AuthorizedEdges();
    List<String> lines = Files.readAllLines(path);
    int lineNo = 0;
    for (String raw : lines) {
      lineNo++;
      String line = raw.strip();
      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }
      int sp = line.indexOf(' ');
      if (sp < 0) {
        log.warn("ignoring malformed authorized_edges line {} (no clientId/key separator)", lineNo);
        continue;
      }
      String clientId = line.substring(0, sp).strip();
      String keySpec = line.substring(sp + 1).strip();
      try {
        PublicKey key = PublicKeyEntry.parsePublicKeyEntry(keySpec).resolvePublicKey(null, null, null);
        edges.add(clientId, key);
      } catch (Exception ex) {
        log.warn("ignoring authorized_edges line {} for clientId={}: {}", lineNo, clientId,
            ex.toString());
      }
    }
    log.info("loaded {} authorized edge key(s) from {}", edges.size(), path);
    return edges;
  }
}
