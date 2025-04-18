/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.io.File;
import java.io.FileNotFoundException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class KeyUtilityTest {
  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @Test
  void readX509PublicKey() {
    final PublicKey publicKey =
        KeyUtility.readX509PublicKey(new File("src/test/resources/keys/ref-es-sig-pubkey.pem"));
    assertThat(publicKey).isNotNull();
  }

  @Test
  void readX509PublicKey_fileNotFound() {
    final File file = new File("non_existing_file");
    assertThatThrownBy(() -> KeyUtility.readX509PublicKey(file))
        .isInstanceOf(IdpCryptoException.class)
        .hasCauseInstanceOf(FileNotFoundException.class);
  }

  @Test
  void readX509PrivateKey_plain() {
    final PrivateKey privateKey =
        KeyUtility.readX509PrivateKeyPlain(
            new File("src/test/resources/keys/ref-es-sig-privkey.pem"));
    assertThat(privateKey).isNotNull();
  }

  @Test
  void readX509PrivateKey_plain_fileNotFound() {
    assertThatThrownBy(() -> KeyUtility.readX509PrivateKeyPlain(new File("non_existing_file")))
        .isInstanceOf(IdpCryptoException.class)
        .hasCauseInstanceOf(FileNotFoundException.class);
  }
}
