/*
 * Copyright (c) 2020 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.crypto;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NonceTest {

    @Test
    public void checkInvalidLowerLimit() {
        assertThatThrownBy(() -> new Nonce().getNonceAsBase64(0)).
                isInstanceOf(IdpCryptoException.class).
                hasMessageContaining("Amount of random bytes");

        assertThatThrownBy(() -> new Nonce().getNonceAsHex(1)).
                isInstanceOf(IdpCryptoException.class).
                hasMessageContaining("string length");
    }

    @Test
    public void checkInvalidUpperLimit() {
        assertThatThrownBy(() -> new Nonce().getNonceAsBase64(513)).
                isInstanceOf(IdpCryptoException.class).
                hasMessageContaining("Amount of random bytes");

        assertThatThrownBy(() -> new Nonce().getNonceAsHex(513)).
                isInstanceOf(IdpCryptoException.class).
                hasMessageContaining("string length is expected to be between");
    }

    @Test
    public void checkExactNonceLength() {
        final int BYTE_AMOUNT = 256;
        String nonce = new Nonce().getNonceAsBase64(BYTE_AMOUNT);
        assertThat(Base64.decode(nonce).length).isEqualTo(BYTE_AMOUNT);

        final int HEXSTR_LEN = 10;
        final String hexStr = new Nonce().getNonceAsHex(HEXSTR_LEN);
        assertThat(hexStr).hasSize(HEXSTR_LEN);
    }

    @Test
    public void checkNonceUnique() {
        final int NONCES_REQUEST_AMOUNT = 1000;
        final Nonce nonce = new Nonce();
        Set<String> nonces = new HashSet<String>();
        for (int i = 0; i < NONCES_REQUEST_AMOUNT; i++) {
            nonces.add(nonce.getNonceAsBase64(32));
            nonces.add(nonce.getNonceAsHex(8));
        }
        assertThat(nonces.size()).isEqualTo(NONCES_REQUEST_AMOUNT * 2);
    }

    @Test
    public void checkIsHexStr() {
        final String hexStr = new Nonce().getNonceAsHex(42);
        assertThat(Hex.decode(hexStr)).isNotEmpty();
    }

    @Test
    public void checkHexRequestedStrLenIsEven() {
        assertThatThrownBy(() -> new Nonce().getNonceAsHex(13)).
                isInstanceOf(IdpCryptoException.class).
                hasMessageContaining("string length is expected to be even");
    }

}
