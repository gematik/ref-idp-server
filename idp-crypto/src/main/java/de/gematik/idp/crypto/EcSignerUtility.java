/*
 * Copyright (c) 2023 gematik GmbH
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

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class EcSignerUtility {

  public static byte[] createEcSignature(final byte[] toBeSignedData, final PrivateKey privateKey) {
    try {
      final Signature signer = Signature.getInstance("SHA256withECDSA");
      signer.initSign(privateKey);
      signer.update(toBeSignedData);
      return signer.sign();
    } catch (final NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new IdpCryptoException(e);
    }
  }

  public static void verifyEcSignatureAndThrowExceptionWhenFail(
      final byte[] toBeSignedData, final PublicKey publicKey, final byte[] signature) {
    try {
      final Signature signer = Signature.getInstance("SHA256withECDSA");
      signer.initVerify(publicKey);
      signer.update(toBeSignedData);
      if (!signer.verify(signature)) {
        throw new IdpCryptoException("Signature validation failed");
      }
    } catch (final NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new IdpCryptoException(e);
    }
  }
}
