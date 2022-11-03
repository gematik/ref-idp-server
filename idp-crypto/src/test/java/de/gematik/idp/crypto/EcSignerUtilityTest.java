/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.crypto.model.PkiIdentity;
import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.security.Security;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class EcSignerUtilityTest {

  private static PkiIdentity identity;
  private static PkiIdentity otherIdentity;

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @BeforeAll
  public static void init() throws IOException {
    identity = certificateDataFrom("src/test/resources/109500969_X114428530_c.ch.aut-ecc.p12");
    otherIdentity = certificateDataFrom("src/test/resources/833621999741600_c.hci.aut-apo-ecc.p12");
  }

  private static PkiIdentity certificateDataFrom(final String filename) throws IOException {
    return CryptoLoader.getIdentityFromP12(FileUtils.readFileToByteArray(new File(filename)), "00");
  }

  @Test
  void createSignatureAndVerifyWithSameKey() {
    final byte[] ecSignature =
        EcSignerUtility.createEcSignature("foobar".getBytes(), identity.getPrivateKey());
    EcSignerUtility.verifyEcSignatureAndThrowExceptionWhenFail(
        "foobar".getBytes(), identity.getCertificate().getPublicKey(), ecSignature);
  }

  @Test
  void createSignatureAndVerifyWithOtherKey_shouldFail() {
    final byte[] toBeSigned = "foobar".getBytes();
    final byte[] ecSignature =
        EcSignerUtility.createEcSignature(toBeSigned, identity.getPrivateKey());
    assertThat(ecSignature).hasSizeGreaterThan(0);
    PublicKey publicKeyOtherIdentity = otherIdentity.getCertificate().getPublicKey();
    assertThat(publicKeyOtherIdentity).isNotNull();

    assertThatThrownBy(
            () ->
                EcSignerUtility.verifyEcSignatureAndThrowExceptionWhenFail(
                    toBeSigned, publicKeyOtherIdentity, ecSignature))
        .isInstanceOf(IdpCryptoException.class);
  }

  @Test
  void createSignatureAndVerifyWithDifferentContent_shouldFail() {
    final byte[] toBeSigned = "foobar".getBytes();
    final byte[] toBeSignedOther = "barfoo".getBytes();
    final byte[] ecSignature =
        EcSignerUtility.createEcSignature(toBeSigned, identity.getPrivateKey());
    assertThat(ecSignature).hasSizeGreaterThan(0);
    PublicKey publicKeyIdentity = identity.getCertificate().getPublicKey();
    assertThat(publicKeyIdentity).isNotNull();

    assertThatThrownBy(
            () ->
                EcSignerUtility.verifyEcSignatureAndThrowExceptionWhenFail(
                    toBeSignedOther, publicKeyIdentity, ecSignature))
        .isInstanceOf(IdpCryptoException.class);
  }
}
