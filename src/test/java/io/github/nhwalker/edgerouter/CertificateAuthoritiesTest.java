package io.github.nhwalker.edgerouter;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;
import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class CertificateAuthoritiesTest {

  private KeyPair ca;
  private KeyPair otherCa;
  private KeyPair edge;
  private CertificateAuthorities cas;

  @BeforeAll
  void keys() throws Exception {
    KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
    ca = gen.genKeyPair();
    otherCa = gen.genKeyPair();
    edge = gen.genKeyPair();
    cas = new CertificateAuthorities();
    cas.addTrustedCa(ca.getPublic());
  }

  @Test
  void validCertFromTrustedCaReturnsUsernameAsClientId() throws Exception {
    OpenSshCertificate cert = userCert(edge, ca, validNow(), List.of("clientA", "clientB"));
    assertThat(cas.authenticate("clientA", cert)).isEqualTo("clientA");
    assertThat(cas.authenticate("clientB", cert)).isEqualTo("clientB");
  }

  @Test
  void bareKeyIsRejected() {
    assertThat(cas.authenticate("clientA", edge.getPublic())).isNull();
  }

  @Test
  void untrustedCaIsRejected() throws Exception {
    OpenSshCertificate cert = userCert(edge, otherCa, validNow(), List.of("clientA"));
    assertThat(cas.authenticate("clientA", cert)).isNull();
  }

  @Test
  void expiredCertIsRejected() throws Exception {
    long[] window = {epoch(Instant.now().minusSeconds(3600)), epoch(Instant.now().minusSeconds(60))};
    OpenSshCertificate cert = userCert(edge, ca, window, List.of("clientA"));
    assertThat(cas.authenticate("clientA", cert)).isNull();
  }

  @Test
  void notYetValidCertIsRejected() throws Exception {
    long[] window = {epoch(Instant.now().plusSeconds(60)), epoch(Instant.now().plusSeconds(3600))};
    OpenSshCertificate cert = userCert(edge, ca, window, List.of("clientA"));
    assertThat(cas.authenticate("clientA", cert)).isNull();
  }

  @Test
  void hostCertificateIsRejected() throws Exception {
    long[] w = validNow();
    OpenSshCertificate cert =
        OpenSshCertificateBuilder.hostCertificate()
            .publicKey(edge.getPublic())
            .id("host")
            .principals(List.of("clientA"))
            .validAfter(w[0])
            .validBefore(w[1])
            .sign(ca);
    assertThat(cas.authenticate("clientA", cert)).isNull();
  }

  @Test
  void usernameNotAPrincipalIsRejected() throws Exception {
    OpenSshCertificate cert = userCert(edge, ca, validNow(), List.of("someoneElse"));
    assertThat(cas.authenticate("clientA", cert)).isNull();
  }

  private static OpenSshCertificate userCert(
      KeyPair subject, KeyPair signer, long[] window, List<String> principals) throws Exception {
    return OpenSshCertificateBuilder.userCertificate()
        .publicKey(subject.getPublic())
        .id("edge")
        .principals(principals)
        .validAfter(window[0])
        .validBefore(window[1])
        .sign(signer);
  }

  private static long[] validNow() {
    return new long[] {epoch(Instant.now().minusSeconds(60)), epoch(Instant.now().plusSeconds(3600))};
  }

  private static long epoch(Instant instant) {
    return instant.getEpochSecond();
  }
}
