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
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import lombok.Data;

@Data
public class IdTokenBuilder {

    private final IdpJwtProcessor jwtProcessor;

    public JsonWebToken buildIdToken(final String clientId) {
        final Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put(ISSUER.getJoseName(), "https://userhost.de");
        claimsMap.put(SUBJECT.getJoseName(), clientId);
        claimsMap.put(AUDIENCE.getJoseName(), "TargetAudience");
        final ZonedDateTime now = ZonedDateTime.now();
        claimsMap.put(ISSUED_AT.getJoseName(), now.toEpochSecond());
        claimsMap.put(NOT_BEFORE.getJoseName(), now.toEpochSecond());

        return jwtProcessor.buildJwt(JwtDescription.builder()
            .claims(claimsMap)
            .expiresAt(now.plusMinutes(5))
            .build());
    }
}
