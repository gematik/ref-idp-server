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

import static de.gematik.idp.IdpConstants.AMR_FAST_TRACK;
import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CONFIRMATION;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;
import static de.gematik.idp.field.ClaimName.TYPE;
import static de.gematik.idp.token.TokenClaimExtraction.extractClaimsFromJwtBody;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.data.IdpKeyDescriptor;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Data;

@Data
public class SsoTokenBuilder {

  private final IdpJwtProcessor jwtProcessor;
  private final String issuerUrl;
  private final Key tokenEncryptionKey;

  public IdpJwe buildSsoToken(
      final X509Certificate certificate,
      final ZonedDateTime issuingTime,
      final List<String> amrString) {
    final Map<String, Object> bodyClaimsMap = new HashMap<>();
    final Map<String, Object> headerClaimsMap = new HashMap<>();
    headerClaimsMap.put(
        ALGORITHM.getJoseName(), BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256);
    bodyClaimsMap.put(
        CONFIRMATION.getJoseName(), IdpKeyDescriptor.constructFromX509Certificate(certificate));
    headerClaimsMap.put(TYPE.getJoseName(), "JWT");
    bodyClaimsMap.put(ISSUER.getJoseName(), issuerUrl);
    bodyClaimsMap.put(ISSUED_AT.getJoseName(), issuingTime.toEpochSecond());
    bodyClaimsMap.put(AUTH_TIME.getJoseName(), issuingTime.toEpochSecond());
    bodyClaimsMap.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), amrString);

    bodyClaimsMap.putAll(X509ClaimExtraction.extractClaimsFromCertificate(certificate));
    return jwtProcessor
        .buildJwt(
            new JwtBuilder()
                .addAllHeaderClaims(headerClaimsMap)
                .addAllBodyClaims(bodyClaimsMap)
                .expiresAt(issuingTime.plusHours(12)))
        .encryptAsNjwt(tokenEncryptionKey);
  }

  public IdpJwe buildSsoTokenFromSektoralIdToken(
      final JsonWebToken idToken, final ZonedDateTime issueingTime) {
    final Map<String, Object> bodyClaimsMap = new HashMap<>();
    final Map<String, Object> headerClaimsMap = new HashMap<>();
    final Map<String, Object> claimsFromIdToken = extractClaimsFromJwtBody(idToken.getRawString());
    headerClaimsMap.put(
        ALGORITHM.getJoseName(), BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256);
    headerClaimsMap.put(TYPE.getJoseName(), "JWT");
    bodyClaimsMap.put(ISSUER.getJoseName(), issuerUrl);
    bodyClaimsMap.put(ISSUED_AT.getJoseName(), issueingTime.toEpochSecond());
    bodyClaimsMap.put(AUTH_TIME.getJoseName(), issueingTime.toEpochSecond());

    bodyClaimsMap.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), List.of(AMR_FAST_TRACK));

    bodyClaimsMap.put(GIVEN_NAME.getJoseName(), claimsFromIdToken.get(GIVEN_NAME.getJoseName()));
    bodyClaimsMap.put(FAMILY_NAME.getJoseName(), claimsFromIdToken.get(FAMILY_NAME.getJoseName()));
    bodyClaimsMap.put(ID_NUMBER.getJoseName(), claimsFromIdToken.get(ID_NUMBER.getJoseName()));
    bodyClaimsMap.put(
        PROFESSION_OID.getJoseName(), claimsFromIdToken.get(PROFESSION_OID.getJoseName()));
    bodyClaimsMap.put(
        ORGANIZATION_NAME.getJoseName(), claimsFromIdToken.get(ORGANIZATION_NAME.getJoseName()));

    return jwtProcessor
        .buildJwt(
            new JwtBuilder()
                .addAllHeaderClaims(headerClaimsMap)
                .addAllBodyClaims(bodyClaimsMap)
                .expiresAt(issueingTime.plusHours(12)))
        .encryptAsNjwt(tokenEncryptionKey);
  }
}
