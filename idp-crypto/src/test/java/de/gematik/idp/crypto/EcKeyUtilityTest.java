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
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class EcKeyUtilityTest {

    private static final String CRV = "P-256";
    private static final String X_BASE_64 = "9bJs27YAflMUWK5nxuiF6XAG0JazuvwRi1EpFK0XKik";
    private static final String Y_BASE_64 = "P8lzNVROgTuwbDqsd8rT1AI3zez94HBsTDpOvajP0rY";

    private final ECPoint EC_POINT = new ECPoint(
        new BigInteger(Base64.getDecoder().decode((String) X_BASE_64)),
        new BigInteger(Base64.getDecoder().decode((String) Y_BASE_64))
    );

    @Test
    void genPublicKey() {
        final PublicKey publicKey = EcKeyUtility.genPublicKey(CRV, EC_POINT);
        assertThat(publicKey).isNotNull();
    }
}
