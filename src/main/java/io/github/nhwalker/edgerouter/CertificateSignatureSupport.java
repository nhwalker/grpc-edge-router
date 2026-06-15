package io.github.nhwalker.edgerouter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import org.apache.sshd.common.NamedFactory;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.signature.Signature;

/**
 * Cert-aware SSH signature factories.
 *
 * <p>MINA 2.15's stock {@code *-cert-v01@openssh.com} signature factories create the same
 * {@link Signature} implementations as their non-certificate counterparts; none of them unwrap an
 * {@link OpenSshCertificate} before initializing the underlying JCE verifier. As a result, the
 * server's public-key auth fails with {@code "No installed provider supports this key:
 * OpenSshCertificateImpl"} when an edge presents a user certificate.
 *
 * <p>These factories wrap the stock certificate signatures and, on {@code initVerifier}, substitute
 * the certificate's underlying public key ({@link OpenSshCertificate#getCertPubKey()}). Registering
 * them on the SSH server (under the same {@code *-cert-v01@openssh.com} names) makes user
 * certificate authentication verify correctly.
 */
final class CertificateSignatureSupport {

  private static final List<BuiltinSignatures> CERT_VARIANTS =
      List.of(
          BuiltinSignatures.ed25519_cert,
          BuiltinSignatures.rsaSHA512_cert,
          BuiltinSignatures.rsaSHA256_cert,
          BuiltinSignatures.nistp256_cert,
          BuiltinSignatures.nistp384_cert,
          BuiltinSignatures.nistp521_cert);

  private CertificateSignatureSupport() {}

  /** Cert-unwrapping signature factories for the supported certificate algorithms. */
  static List<NamedFactory<Signature>> certificateFactories() {
    List<NamedFactory<Signature>> factories = new ArrayList<>();
    for (BuiltinSignatures variant : CERT_VARIANTS) {
      if (variant.isSupported()) {
        factories.add(new UnwrappingFactory(variant));
      }
    }
    return factories;
  }

  private record UnwrappingFactory(BuiltinSignatures variant) implements NamedFactory<Signature> {
    @Override
    public String getName() {
      return variant.getName();
    }

    @Override
    public Signature create() {
      return new UnwrappingSignature(variant.create());
    }
  }

  /** Delegates to a stock signature but unwraps a certificate to its underlying key on verify-init. */
  private static final class UnwrappingSignature implements Signature {
    private final Signature delegate;

    UnwrappingSignature(Signature delegate) {
      this.delegate = delegate;
    }

    @Override
    public String getAlgorithm() {
      return delegate.getAlgorithm();
    }

    @Override
    public void initVerifier(SessionContext session, PublicKey key) throws Exception {
      PublicKey verifyKey = key instanceof OpenSshCertificate cert ? cert.getCertPubKey() : key;
      delegate.initVerifier(session, verifyKey);
    }

    @Override
    public void initSigner(SessionContext session, PrivateKey key) throws Exception {
      delegate.initSigner(session, key);
    }

    @Override
    public void update(SessionContext session, byte[] hash, int off, int len) throws Exception {
      delegate.update(session, hash, off, len);
    }

    @Override
    public boolean verify(SessionContext session, byte[] sig) throws Exception {
      return delegate.verify(session, sig);
    }

    @Override
    public byte[] sign(SessionContext session) throws Exception {
      return delegate.sign(session);
    }
  }
}
