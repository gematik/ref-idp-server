/*
 * Copyright (c) 2021 gematik GmbH
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

package de.gematik.idp.token;

import static de.gematik.idp.field.ClaimName.*;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.field.ClaimName;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.Data;
import org.apache.commons.lang3.ArrayUtils;

@Data
public class IdTokenBuilder {

    private static final Set<String> requiredClaims = Stream.of(PROFESSION_OID, GIVEN_NAME, FAMILY_NAME,
        ORGANIZATION_NAME, ID_NUMBER, AUTHENTICATION_CLASS_REFERENCE, CLIENT_ID, SCOPE, AUTH_TIME)
        .map(ClaimName::getJoseName)
        .collect(Collectors.toSet());
    private final IdpJwtProcessor jwtProcessor;
    private final String uriIdpServer;

    public JsonWebToken buildIdToken(final String clientId, final JsonWebToken authenticationToken,
        final byte[] accesTokenHash) {
        final Map<String, Object> claimsMap = new HashMap<>();
        final ZonedDateTime now = ZonedDateTime.now();
        final String atHashValue = Base64.getEncoder().encodeToString(
            ArrayUtils.subarray(accesTokenHash, 0, 16));

        claimsMap.put(ISSUER.getJoseName(), uriIdpServer);
        claimsMap.put(SUBJECT.getJoseName(), clientId);
        claimsMap.put(AUDIENCE.getJoseName(), IdpConstants.AUDIENCE);
        claimsMap.put(ISSUED_AT.getJoseName(), now.toEpochSecond());

        claimsMap.put(PROFESSION_OID.getJoseName(), authenticationToken.getBodyClaim(PROFESSION_OID).orElse(""));
        claimsMap
            .put(ORGANIZATION_NAME.getJoseName(), authenticationToken.getBodyClaim(ORGANIZATION_NAME).orElse(""));
        claimsMap.put(ID_NUMBER.getJoseName(), authenticationToken.getBodyClaim(ID_NUMBER).orElse(""));
        claimsMap.put(GIVEN_NAME.getJoseName(), authenticationToken.getBodyClaim(GIVEN_NAME).orElse(""));
        claimsMap.put(FAMILY_NAME.getJoseName(), authenticationToken.getBodyClaim(FAMILY_NAME).orElse(""));
        claimsMap.put(AUTH_TIME.getJoseName(), authenticationToken.getBodyClaim(AUTH_TIME).orElse(""));
        claimsMap.put(NONCE.getJoseName(), authenticationToken.getBodyClaim(NONCE).orElse(""));
        claimsMap.put(AUTHORIZED_PARTY.getJoseName(), authenticationToken.getBodyClaim(CLIENT_ID).get());
        claimsMap.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), "[\"mfa\", \"sc\", \"pin\"]");
        claimsMap.put(AUTHENTICATION_CLASS_REFERENCE.getJoseName(), IdpConstants.EIDAS_LOA_HIGH);
        claimsMap.put(ACCESS_TOKEN_HASH.getJoseName(), atHashValue);

        final Map<String, Object> headerClaims = new HashMap<>();
        headerClaims.put(TYPE.getJoseName(), "JWT");

        return jwtProcessor.buildJwt(new JwtBuilder()
            .addAllBodyClaims(claimsMap)
            .addAllHeaderClaims(headerClaims)
            .expiresAt(now.plusMinutes(5)));
    }
}
