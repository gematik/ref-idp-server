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

package de.gematik.idp.fachdienst.services;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.token.JsonWebToken;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EntityStmntIdpsService {

    /**
     * Entity statements of all Idp-Sektorals
     */
    private static final Map<String, String> IDPS_ENTITY_STATEMENTS;

    static {
        IDPS_ENTITY_STATEMENTS = new HashMap<>();
    }

    public String getEntityStatement(final String issuer) {
        updateStatementIfExpiredAndNewIsAvailable(issuer);
        return IDPS_ENTITY_STATEMENTS.get(issuer);
    }

    public String getAuthorizationEndpoint(final String entityStmnt) {
        final Map<String, Object> bodyClaims = new JsonWebToken(entityStmnt).getBodyClaims();
        final Map<String, Object> metadata = getInnerClaimMap(bodyClaims, "metadata");
        final Map<String, Object> openidProvider = getInnerClaimMap(metadata, "openid_provider");
        return Objects.requireNonNull((String) openidProvider.get("authorization_endpoint"),
            "missing claim: authorization_endpoint");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> getInnerClaimMap(final Map<String, Object> claimMap, final String key) {
        return Objects.requireNonNull(
            (Map<String, Object>) claimMap.get(key), "missing claim: " + key);
    }

    private void updateStatementIfExpiredAndNewIsAvailable(final String issuer) {
        if (IDPS_ENTITY_STATEMENTS.containsKey(issuer)) {
            if (stmntIsEpired(IDPS_ENTITY_STATEMENTS.get(issuer))) {
                fetchEntityStatement(issuer);
            }
            return;
        }
        fetchEntityStatement(issuer);
    }

    private boolean stmntIsEpired(final String entityStmnt) {
        final Map<String, Object> bodyClaims = new JsonWebToken(entityStmnt).getBodyClaims();
        final Long exp = (Long) bodyClaims.get("exp");
        return isExpired(exp);
    }

    private boolean isExpired(final Long exp) {
        final ZonedDateTime currentUtcTime = ZonedDateTime.now(ZoneOffset.UTC);
        final ZonedDateTime expiredUtcTime = ZonedDateTime.ofInstant(Instant.ofEpochSecond(exp), ZoneOffset.UTC);
        return currentUtcTime.isAfter(expiredUtcTime);
    }

    private void fetchEntityStatement(final String issuer) {
        final HttpResponse<String> resp = Unirest.get(issuer + IdpConstants.ENTITY_STATEMENT_ENDPOINT)
            .asString();
        IDPS_ENTITY_STATEMENTS.put(issuer, resp.getBody());
    }
}
