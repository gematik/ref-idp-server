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

package de.gematik.idp.token;

import static de.gematik.idp.field.ClaimName.*;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtDescription;
import de.gematik.idp.exceptions.RequiredClaimException;
import de.gematik.idp.field.ClaimName;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import lombok.Data;
import org.apache.commons.lang3.ObjectUtils;

@Data
public class AccessTokenBuilder {

    private final IdpJwtProcessor jwtProcessor;
    private final String uriIdpServer;
    private static final List<ClaimName> requiredClaims = Arrays.asList(PROFESSION_OID, ID_NUMBER);

    public JsonWebToken buildAccessToken(final JsonWebToken authenticationToken) {
        final ZonedDateTime now = ZonedDateTime.now();
        final Map<String, Object> claimsMap = new HashMap<>();

        claimsMap.putAll(authenticationToken.getBodyClaims());
        claimsMap.put(ISSUED_AT.getJoseName(), now.toEpochSecond());
        claimsMap.put(NOT_BEFORE.getJoseName(), now.toEpochSecond());
        claimsMap.put(AUTH_TIME.getJoseName(), now.toEpochSecond());
        claimsMap.put(ISSUER.getJoseName(), uriIdpServer);

        for (final ClaimName requiredClaim : requiredClaims) {
            final Object claim = claimsMap.get(requiredClaim.getJoseName());
            if (ObjectUtils.isEmpty(claim)) {
                throw new RequiredClaimException(
                    String.format("claim '%s' does not exits, is null or empty", requiredClaim.getJoseName()));
            }
        }

        return jwtProcessor.buildJwt(JwtDescription.builder()
            .claims(claimsMap)
            .expiresAt(now.plusMinutes(5))
            .build());
    }
}
