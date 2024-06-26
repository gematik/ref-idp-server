/*
 *  Copyright 2024 gematik GmbH
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

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.*;

import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.KeyUtility;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.file.ResourceReader;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class FederationPubKeyTest {
  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @SneakyThrows
  @Test
  void buildJwkWithX5c() {
    final X509Certificate certificate =
        CryptoLoader.getCertificateFromPem(
            FileUtils.readFileToByteArray(
                ResourceReader.getFileFromResourceAsTmpFile("idp_sig.pem")));
    final FederationPubKey federationPubKey = new FederationPubKey();
    federationPubKey.setCertificate(Optional.of(certificate));

    assertDoesNotThrow(federationPubKey::buildJwkWithX5c);
  }

  @SneakyThrows
  @Test
  void buildJwkWithoutX5c() {
    final PublicKey publicKey =
        KeyUtility.readX509PublicKey(
            ResourceReader.getFileFromResourceAsTmpFile("keys/ref-es-sig-pubkey.pem"));
    final FederationPubKey federationPubKey = new FederationPubKey();
    federationPubKey.setKeyId("keyId42");
    federationPubKey.setPublicKey(Optional.ofNullable(publicKey));

    assertDoesNotThrow(federationPubKey::buildJwkWithoutX5c);
  }

  @Test
  void federationPubkeyInvalid() {
    final FederationPubKey federationPubKey = new FederationPubKey();
    assertThatThrownBy(federationPubKey::buildJwkWithoutX5c).isInstanceOf(IdpCryptoException.class);
  }
}
