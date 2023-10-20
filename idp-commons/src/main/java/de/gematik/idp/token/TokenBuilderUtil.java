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

package de.gematik.idp.token;

import static de.gematik.idp.field.ClaimName.DISPLAY_NAME;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;

import java.util.Map;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class TokenBuilderUtil {

  public static String buildSubjectClaim(
      final String audClaim, final String idNummerClaim, final String serverSubjectSalt) {
    return Base64.encodeBase64URLSafeString(
        DigestUtils.sha256(audClaim + idNummerClaim + serverSubjectSalt));
  }

  private static String buildDisplayNameFromGivenNameAndFamilyName(
      final String givenName, final String familyName) {
    if (givenName == null || familyName == null) {
      return null;
    } else {
      return givenName + " " + familyName;
    }
  }

  public static void addDisplayNameToBodyClaims(
      final Optional<Object> displayName, final Map<String, Object> claimsMap) {
    if (displayName.isPresent()) {
      claimsMap.put(DISPLAY_NAME.getJoseName(), displayName.get());
    } else {
      claimsMap.put(
          DISPLAY_NAME.getJoseName(),
          buildDisplayNameFromGivenNameAndFamilyName(
              (String) claimsMap.get(GIVEN_NAME.getJoseName()),
              (String) claimsMap.get(FAMILY_NAME.getJoseName())));
    }
  }
}
