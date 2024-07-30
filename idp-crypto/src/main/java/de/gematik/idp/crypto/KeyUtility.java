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

package de.gematik.idp.crypto;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class KeyUtility {
  public static PublicKey readX509PublicKey(final File pemFile) {
    try (final FileReader keyReader = new FileReader(pemFile)) {
      final PEMParser pemParser = new PEMParser(keyReader);
      final SubjectPublicKeyInfo subjectPublicKeyInfo =
          (SubjectPublicKeyInfo) pemParser.readObject();
      return convertToBCECPublicKey(subjectPublicKeyInfo);
    } catch (final IOException
        | NoSuchAlgorithmException
        | NoSuchProviderException
        | InvalidKeySpecException e) {
      throw new IdpCryptoException(e);
    }
  }

  private static BCECPublicKey convertToBCECPublicKey(
      final SubjectPublicKeyInfo subjectPublicKeyInfo)
      throws PEMException,
          NoSuchAlgorithmException,
          NoSuchProviderException,
          InvalidKeySpecException {
    // Convert SubjectPublicKeyInfo to PublicKey
    final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    final PublicKey publicKey = converter.getPublicKey(subjectPublicKeyInfo);

    // Convert PublicKey to BCECPublicKey
    final KeyFactory keyFactory = KeyFactory.getInstance("EC", "BC");
    final ECPublicKeySpec keySpec;
    if (publicKey instanceof final java.security.interfaces.ECPublicKey ecPublicKey) {
      keySpec = new ECPublicKeySpec(ecPublicKey.getW(), ecPublicKey.getParams());
      return (BCECPublicKey) keyFactory.generatePublic(keySpec);
    } else {
      throw new IdpCryptoException("Public key is not an instance of ECPublicKey");
    }
  }

  public static PrivateKey readX509PrivateKeyPlain(final File pemFile) {
    try (final FileReader keyReader = new FileReader(pemFile)) {

      final PEMParser pemParser = new PEMParser(keyReader);
      final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
      final PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());

      return converter.getPrivateKey(privateKeyInfo);
    } catch (final IOException e) {
      throw new IdpCryptoException(e);
    }
  }
}
