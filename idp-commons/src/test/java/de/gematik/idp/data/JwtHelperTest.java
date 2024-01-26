/*
 *  Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.data;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.KeyUtility;
import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Security;
import java.util.Optional;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class JwtHelperTest {
  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private static final String JWS_VALID_SIGNATURE =
      "eyJhbGciOiJCUDI1NlIxIiwia2lkIjoicHVrX2lkcF9zaWciLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2lkcC1yZWYuYXBwLnRpLWRpZW5zdGUuZGUiLCJpYXQiOjE2MzcyMjE5MTUsImV4cCI6MTYzNzIyMjA5NSwidG9rZW5fdHlwZSI6ImNoYWxsZW5nZSIsImp0aSI6ImJhYzdlOTdhLTkyMWMtNDZlOS1hODM2LTNkYjUyMTgxNDMyNSIsInNuYyI6IjRlM2ZjN2FhNTQwNDRhZDQ4MjRkM2VkMzVlNzIxNjg4Iiwic2NvcGUiOiJwYWlyaW5nIG9wZW5pZCIsImNvZGVfY2hhbGxlbmdlIjoiQnlTX3RDeWs4SkwwS1ltT1RNV29rNm9nMmJUS3RBc2hrcE1zWDBjZnhJRSIsImNvZGVfY2hhbGxlbmdlX21ldGhvZCI6IlMyNTYiLCJyZXNwb25zZV90eXBlIjoiY29kZSIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vcmVkaXJlY3QuZ2VtYXRpay5kZS9lcmV6ZXB0IiwiY2xpZW50X2lkIjoiZVJlemVwdEFwcCIsInN0YXRlIjoiTGF0aXpVWVVHTUNaRTN4WiIsIm5vbmNlIjoieVY3a1hmTnVhSDNtM05qNkxjc1UifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

  @SneakyThrows
  @Test
  void invalidateJsonSignatureTest() {
    assertThat((JwtHelper.invalidateJsonSignature(JWS_VALID_SIGNATURE).split("\\."))[2])
        .isEqualTo(
            "Is8Ag-3Z0DwWS7RXCSRDPy1_m3bZatBB12PFOmTa8cBw0WrzixE23VL6xFeBFAFowlez-QQKU_WRhyPkX18-wQ");
  }

  @SneakyThrows
  @Test
  void getJwksWithX5c() {
    final FederationPubKey federationPubKey = getFederationPubKeyWithX5c();
    assertThat(JwtHelper.getJwks(federationPubKey).getKeys()).hasSize(1);
  }

  @SneakyThrows
  @Test
  void getJwksWithoutX5c() {
    final FederationPubKey federationPubKey = getFederationPubKeyWithoutX5c();
    assertThat(JwtHelper.getJwks(federationPubKey).getKeys()).hasSize(1);
  }

  @SneakyThrows
  @Test
  void getJwksWithAndWithoutX5c() {
    final FederationPubKey federationPubKeyWithoutCert = getFederationPubKeyWithoutX5c();
    final FederationPubKey federationPubKeyWithX5c = getFederationPubKeyWithX5c();
    assertThat(JwtHelper.getJwks(federationPubKeyWithX5c, federationPubKeyWithoutCert).getKeys())
        .hasSize(2);
  }

  private static FederationPubKey getFederationPubKeyWithX5c() throws IOException {
    final FederationPubKey federationPubKey = new FederationPubKey();
    federationPubKey.setCertificate(
        Optional.ofNullable(
            CryptoLoader.getCertificateFromP12(
                FileUtils.readFileToByteArray(
                    new File("src/test/resources/109500969_X114428530_c.ch.aut-ecc.p12")),
                "00")));
    federationPubKey.setPublicKey(Optional.empty());
    federationPubKey.setKeyId("anyKeyId");
    federationPubKey.setUse(Optional.of("anyUse"));
    return federationPubKey;
  }

  private static FederationPubKey getFederationPubKeyWithoutX5c() {
    final FederationPubKey federationPubKey = new FederationPubKey();
    final PublicKey publicKey =
        KeyUtility.readX509PublicKey(new File("src/test/resources/keys/ref-es-sig-pubkey.pem"));
    federationPubKey.setPublicKey(Optional.of(publicKey));
    federationPubKey.setCertificate(Optional.empty());
    federationPubKey.setKeyId("anyKeyId");
    federationPubKey.setUse(Optional.of("anyUse"));
    return federationPubKey;
  }
}
