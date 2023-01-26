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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

class NonceTest {

  @Test
  void checkInvalidLowerLimit() {
    assertThatThrownBy(() -> Nonce.getNonceAsBase64UrlEncodedString(0))
        .isInstanceOf(IdpCryptoException.class)
        .hasMessageContaining("Amount of random bytes");

    assertThatThrownBy(() -> Nonce.getNonceAsHex(1))
        .isInstanceOf(IdpCryptoException.class)
        .hasMessageContaining("string length");
  }

  @Test
  void checkInvalidUpperLimit() {
    assertThatThrownBy(() -> Nonce.getNonceAsBase64UrlEncodedString(513))
        .isInstanceOf(IdpCryptoException.class)
        .hasMessageContaining("Amount of random bytes");

    assertThatThrownBy(() -> Nonce.getNonceAsHex(513))
        .isInstanceOf(IdpCryptoException.class)
        .hasMessageContaining("string length is expected to be between");
  }

  @Test
  void checkExactNonceLength() {
    final int BYTE_AMOUNT = 24;
    final String nonce = Nonce.getNonceAsBase64UrlEncodedString(BYTE_AMOUNT);
    assertThat(Base64.getUrlDecoder().decode(nonce)).hasSize(BYTE_AMOUNT);

    final int HEXSTR_LEN = 10;
    final String hexStr = Nonce.getNonceAsHex(HEXSTR_LEN);
    assertThat(hexStr).hasSize(HEXSTR_LEN);
  }

  @Test
  void checkResultingBase64NonceLength() {
    final int BYTE_AMOUNT = 24;
    final String nonce = Nonce.getNonceAsBase64UrlEncodedString(BYTE_AMOUNT);
    assertThat(nonce).hasSize(4 * BYTE_AMOUNT / 3);
  }

  @Test
  void checkNonceUnique() {
    final int NONCES_REQUEST_AMOUNT = 1000;
    final Set<String> nonces = new HashSet<>();
    for (int i = 0; i < NONCES_REQUEST_AMOUNT; i++) {
      nonces.add(Nonce.getNonceAsBase64UrlEncodedString(32));
      nonces.add(Nonce.getNonceAsHex(8));
    }
    assertThat(nonces).hasSize(NONCES_REQUEST_AMOUNT * 2);
  }

  @Test
  void checkIsHexStr() {
    final String hexStr = Nonce.getNonceAsHex(42);
    assertThat(Hex.decode(hexStr)).isNotEmpty();
  }

  @Test
  void checkHexRequestedStrLenIsEven() {
    assertThatThrownBy(() -> Nonce.getNonceAsHex(13))
        .isInstanceOf(IdpCryptoException.class)
        .hasMessageContaining("string length is expected to be even");
  }
}
