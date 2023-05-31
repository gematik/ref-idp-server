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

package de.gematik.idp.field;

import de.gematik.idp.crypto.Nonce;
import java.util.Base64;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class ClientUtilities {

  public static String generateCodeChallenge(final String codeVerifier) {
    // see https://tools.ietf.org/html/rfc7636#section-4.2
    return new String(
        Base64.getUrlEncoder().withoutPadding().encode(DigestUtils.sha256(codeVerifier)));
  }

  public static String generateCodeVerifier() {
    return generateCodeVerifier(Nonce.randomBytes(32));
  }

  public static String generateCodeVerifier(final byte[] randomOctets) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(randomOctets);
  }
}
