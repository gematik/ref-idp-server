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

package de.gematik.idp.server.data;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.crypto.KeyUtility;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.file.ResourceReader;
import java.io.File;
import java.security.Security;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class RsaTest {
  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  @SneakyThrows
  @Test
  void PubKeyFromFile_RsaNotSupported() {
    final File file =
        ResourceReader.getFileFromResourceAsTmpFile("833621999741600_c.hci.aut-apo-rsa_pubkey.pem");
    assertThatThrownBy(() -> KeyUtility.readX509PublicKey(file))
        .isInstanceOf(IdpCryptoException.class);
  }
}
