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

import static de.gematik.idp.EnvHelper.getSystemProperty;
import static de.gematik.idp.IdpConstants.ENTITY_LISTING_ENDPOINT;
import de.gematik.idp.token.JsonWebToken;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EntityListService {

    private static final String OLD_DEFAULT_ENTITY_LIST_AS_JWS = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InB1a19mZWRfc2lnIn0.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjYyOTQ1IiwiaWF0IjoxNjQ1NDQwNDU1LCJleHAiOjE2NDU1MjY4NTUsImlkcF9lbnRpdHlfbGlzdCI6W3sibmFtZSI6IklEUF9TRUtUT1JBTCIsImlzcyI6Imh0dHA6Ly8xMjcuMC4wLjE6ODA4MiIsImxvZ29fdXJpIjoidG9kby1sb2dvIiwidXNlcl90eXBlX3N1cHBvcnRlZCI6InRvZG8tdXRzdXBwIn1dfQ.QPurTcnTeisAyZ9AujIGy__Z-6kYLT_agDTfBX4sKsVbMxVUevj-tW5eTzqh6nXMzRlYXbBEKNWtm64XnPdk3Q";
    private String entityListAsJws = OLD_DEFAULT_ENTITY_LIST_AS_JWS;

    public String getEntityList() {
        updateEntityListIfExpiredAndNewIsAvailable();
        return entityListAsJws;
    }

    private void updateEntityListIfExpiredAndNewIsAvailable() {
        final Map<String, Object> bodyClaims = new JsonWebToken(entityListAsJws).getBodyClaims();
        final Long exp = (Long) bodyClaims.get("exp");
        if (isExpired(exp)) {
            final Optional<String> s = fetchEntityList();
            if (s.isPresent()) {
                entityListAsJws = s.get();
            }
        }
    }

    private boolean isExpired(final Long exp) {
        final ZonedDateTime currentUtcTime = ZonedDateTime.now(ZoneOffset.UTC);
        final ZonedDateTime expiredUtcTime = ZonedDateTime.ofInstant(Instant.ofEpochSecond(exp), ZoneOffset.UTC);
        return currentUtcTime.isAfter(expiredUtcTime);
    }

    private Optional<String> fetchEntityList() {
        final String fedmasterUrl =
            getOtherServerUrl("IDP_FEDMASTER").orElse("IDP_FEDMASTER_PORT.NOT.SET.IN.ENVIRNOMENT")
                + ENTITY_LISTING_ENDPOINT;
        try {
            final HttpResponse<String> response = Unirest.get(fedmasterUrl).asString();
            return Optional.of(new JsonWebToken(response.getBody()).getRawString());
        } catch (final UnirestException e) {
            return Optional.empty();
        }
    }

    private static Optional<String> getOtherServerUrl(final String serverEnvName) {
        try {
            final StringBuilder str = new StringBuilder();
            str.append(getSystemProperty(serverEnvName).orElse("http://127.0.0.1"));
            str.append(":");
            str.append(getSystemProperty(serverEnvName + "_PORT").orElseThrow());
            return Optional.of(str.toString());
        } catch (final NoSuchElementException e) {
            return Optional.empty();
        }
    }
}
