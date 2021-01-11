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

import static de.gematik.idp.field.ClaimName.ALGORITHM;
import static de.gematik.idp.field.ClaimName.AUDIENCE;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.JWKS_URI;
import static de.gematik.idp.field.ClaimName.NOT_BEFORE;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;
import static de.gematik.idp.field.ClaimName.SUBJECT;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.Rfc;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class IdTokenBuilderTest {

    private static final String uriIdpServer = "https://idp.zentral.idp.splitdns.ti-dienste.de";
    private static final long maxIdTokenExpirationInSec = 86400;

    private JsonWebToken idToken;

    @BeforeEach
    public void init(@PkiKeyResolver.Filename("authz_rsa") final PkiIdentity clientIdentity) {
        final Map<String, Object> bodyClaims = new HashMap<>();
        bodyClaims.put(PROFESSION_OID.getJoseName(), "profession");
        bodyClaims.put(ORGANIZATION_NAME.getJoseName(), "organization");
        bodyClaims.put(ID_NUMBER.getJoseName(), "id_number");
        bodyClaims.put(GIVEN_NAME.getJoseName(), "given_name");
        bodyClaims.put(FAMILY_NAME.getJoseName(), "family_name");
        bodyClaims.put(JWKS_URI.getJoseName(), "jwks_uri");
        final JsonWebToken authenticationToken = new JsonWebToken("", Map.of("headerNotCopy", "headerNotCopy"),
            bodyClaims);
        final IdTokenBuilder idTokenBuilder = new IdTokenBuilder(new IdpJwtProcessor(clientIdentity), uriIdpServer);
        idToken = idTokenBuilder.buildIdToken(IdpConstants.CLIENT_ID, authenticationToken);
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 2 ID Token")
    @Afo("A_20313")
    @Afo("TODO A_20297/ML-110385?")
    @Test
    public void checkIdTokenClaims() {
        assertThat(idToken.getBodyClaims())
            .containsEntry(ISSUER.getJoseName(), uriIdpServer)
            .containsEntry(SUBJECT.getJoseName(), IdpConstants.CLIENT_ID)
            .containsEntry(AUDIENCE.getJoseName(), IdpConstants.AUDIENCE)
            .containsKey(EXPIRES_AT.getJoseName())
            .containsKey(ISSUED_AT.getJoseName())
            .containsKey(NOT_BEFORE.getJoseName())
            .containsEntry(PROFESSION_OID.getJoseName(), "profession")
            .containsEntry(ORGANIZATION_NAME.getJoseName(), "organization")
            .containsEntry(ID_NUMBER.getJoseName(), "id_number")
            .containsEntry(GIVEN_NAME.getJoseName(), "given_name")
            .containsEntry(FAMILY_NAME.getJoseName(), "family_name")
            .doesNotContainKey(JWKS_URI.getJoseName());
        assertThat(idToken.getHeaderClaims())
            .containsKey(ALGORITHM.getJoseName())
            .containsKey(EXPIRES_AT.getJoseName())
            .doesNotContainKey("headerNotCopy");
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 2 ID Token")
    @Afo("A_20462")
    @Test
    public void checkIdTokenClaimTimestamps() {
        final long now = ZonedDateTime.now().toEpochSecond();
        final long expHeader = idToken.getExpiresAt().toEpochSecond();
        final long expBody = idToken.getExpiresAtBody().toEpochSecond();
        final long iat = idToken.getIssuedAt().toEpochSecond();
        final long nbf = idToken.getNotBefore().toEpochSecond();

        assertThat(now).isGreaterThanOrEqualTo(iat);
        assertThat(now).isGreaterThanOrEqualTo(nbf);
        assertThat(now).isLessThan(expHeader);
        assertThat(now).isLessThan(expBody);
        assertThat(expHeader - now).isLessThan(maxIdTokenExpirationInSec);
    }
}
