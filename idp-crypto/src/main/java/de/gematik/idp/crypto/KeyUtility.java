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
import java.security.PrivateKey;
import java.security.PublicKey;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class KeyUtility {
  public static PublicKey readX509PublicKey(final File pemFile) {
    try (final FileReader keyReader = new FileReader(pemFile)) {
      final PEMParser pemParser = new PEMParser(keyReader);
      final JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
      final SubjectPublicKeyInfo publicKeyInfo =
          SubjectPublicKeyInfo.getInstance(pemParser.readObject());
      return converter.getPublicKey(publicKeyInfo);
    } catch (final IOException e) {
      throw new IdpCryptoException(e);
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
