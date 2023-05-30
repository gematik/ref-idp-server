/*
 *  Copyright 2023 gematik GmbH
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

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.spec.ECPoint;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class EcKeyUtilityTest {

  private static final String CRV = "P-256";
  private static final String X_BASE_64 = "9bJs27YAflMUWK5nxuiF6XAG0JazuvwRi1EpFK0XKik";
  // X_HEX = "f5b26cdbb6007e531458ae67c6e885e97006d096b3bafc118b512914ad172a29";
  private static final String X_DEC =
      "111131897992431631128378725387678835855683379851052166139321377297662599440937";
  private static final String Y_BASE_64 = "P8lzNVROgTuwbDqsd8rT1AI3zez94HBsTDpOvajP0rY";
  // Y_HEX = "3fc97335544e813bb06c3aac77cad3d40237cdecfde0706c4c3a4ebda8cfd2b6";
  private static final String Y_DEC =
      "28851640859351819500294281742331597709010251938378060295576418341791976116918";

  @Test
  void genPublicKey() {
    final ECPoint ecPoint =
        new ECPoint(
            new BigInteger(Base64.getDecoder().decode(X_BASE_64)),
            new BigInteger(Base64.getDecoder().decode(Y_BASE_64)));
    final PublicKey publicKey = EcKeyUtility.genPublicKey(CRV, ecPoint);
    assertThat(publicKey).isNotNull();
  }

  @Test
  void ecPoints() {
    final ECPoint ecPoint1 =
        new ECPoint(
            new BigInteger(1, Base64.getDecoder().decode(X_BASE_64)),
            new BigInteger(1, Base64.getDecoder().decode(Y_BASE_64)));

    final ECPoint ecPoint2 = new ECPoint(new BigInteger(X_DEC), new BigInteger(Y_DEC));

    assertThat(ecPoint1).isEqualTo(ecPoint2);
  }
}
