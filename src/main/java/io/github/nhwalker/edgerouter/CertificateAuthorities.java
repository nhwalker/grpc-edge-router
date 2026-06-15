package io.github.nhwalker.edgerouter;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Trust anchor for edge identities. Edges authenticate with an OpenSSH <em>user certificate</em>
 * signed by a trusted certificate authority (CA); the CA stamps the edge's identity into the
 * certificate. The gateway trusts a small set of CA public keys rather than a per-edge key list.
 *
 * <p>An edge's {@code clientId} is its SSH username, which must be one of the certificate's
 * principals — so the CA controls exactly which clientIds an edge may assume.
 *
 * <p>Because MINA's server-side public-key auth does <em>not</em> verify a user certificate's CA
 * signature or CA trust (it only checks type, validity window, principals, and the user's
 * possession signature), this class performs those checks itself: CA trust by fingerprint and
 * verification of the certificate's CA signature (mirroring MINA's own host-certificate path).
 */
public final class CertificateAuthorities {

  private static final Logger log = LoggerFactory.getLogger(CertificateAuthorities.class);

  // Trusted CA public keys, matched by SHA-256 fingerprint.
  private final CopyOnWriteArrayList<String> trustedFingerprints = new CopyOnWriteArrayList<>();
  private final CopyOnWriteArrayList<PublicKey> trustedKeys = new CopyOnWriteArrayList<>();

  // Self-contained signature factories so CA-signature verification needs no live SSH session.
  private final List<NamedFactory<Signature>> signatureFactories = BuiltinSignatures.VALUES.stream()
      .map(f -> (NamedFactory<Signature>) f)
      .toList();

  /** Trust a CA public key. Edges presenting certs signed by this CA are accepted. */
  public void addTrustedCa(PublicKey caKey) {
    trustedFingerprints.add(KeyUtils.getFingerPrint(caKey));
    trustedKeys.add(caKey);
  }

  public int size() {
    return trustedKeys.size();
  }

  /**
   * Validate a presented public key and return the authenticated {@code clientId}, or {@code null}
   * to reject. The key must be a user certificate signed by a trusted CA, currently valid, whose
   * principals include {@code username}.
   */
  public String authenticate(String username, PublicKey presented) {
    if (username == null || username.isEmpty()) {
      return reject(username, "empty username");
    }
    if (!(presented instanceof OpenSshCertificate cert)) {
      return reject(username, "a bare public key was presented; a user certificate is required");
    }
    if (cert.getType() != OpenSshCertificate.Type.USER) {
      return reject(username, "certificate is not a user certificate");
    }
    if (!OpenSshCertificate.isValidNow(cert)) {
      return reject(username, "certificate is outside its validity window");
    }
    if (!isTrustedCa(cert.getCaPubKey())) {
      return reject(username, "certificate was signed by an untrusted CA");
    }
    if (!caSignatureValid(cert)) {
      return reject(username, "certificate CA signature failed verification");
    }
    Collection<String> principals = cert.getPrincipals();
    if (principals == null || principals.isEmpty() || !principals.contains(username)) {
      return reject(username, "username is not a listed certificate principal");
    }
    log.info(
        "edge authenticated: clientId={} certId={} serial={}",
        username,
        cert.getId(),
        cert.getSerial());
    return username;
  }

  private boolean isTrustedCa(PublicKey caKey) {
    return caKey != null && trustedFingerprints.contains(KeyUtils.getFingerPrint(caKey));
  }

  /**
   * Verify the certificate's CA signature, mirroring MINA's host-certificate verification
   * ({@code DHGClient.verifyCertificate}): resolve a {@link Signature} for the certificate's
   * signature algorithm, then verify {@code getMessage()} against {@code getSignature()} using the
   * CA public key.
   */
  private boolean caSignatureValid(OpenSshCertificate cert) {
    try {
      Signature verifier =
          NamedFactory.create(signatureFactories, cert.getSignatureAlgorithm());
      if (verifier == null) {
        log.warn("no signature factory for certificate algorithm '{}'", cert.getSignatureAlgorithm());
        return false;
      }
      verifier.initVerifier(null, cert.getCaPubKey());
      verifier.update(null, cert.getMessage());
      return verifier.verify(null, cert.getSignature());
    } catch (Exception ex) {
      log.warn("error verifying certificate CA signature: {}", ex.toString());
      return false;
    }
  }

  private String reject(String username, String reason) {
    log.warn("rejected SSH auth (username={}): {}", username, reason);
    return null;
  }

  /**
   * Load trusted CA public keys from a file: one OpenSSH public-key line per CA (blank lines and
   * lines starting with {@code #} are ignored).
   */
  public static CertificateAuthorities fromFile(Path path) throws IOException {
    CertificateAuthorities cas = new CertificateAuthorities();
    int lineNo = 0;
    for (String raw : Files.readAllLines(path)) {
      lineNo++;
      String line = raw.strip();
      if (line.isEmpty() || line.startsWith("#")) {
        continue;
      }
      try {
        PublicKey key = PublicKeyEntry.parsePublicKeyEntry(line).resolvePublicKey(null, null, null);
        cas.addTrustedCa(key);
      } catch (Exception ex) {
        log.warn("ignoring trusted-CA line {}: {}", lineNo, ex.toString());
      }
    }
    log.info("loaded {} trusted CA key(s) from {}", cas.size(), path);
    return cas;
  }
}
