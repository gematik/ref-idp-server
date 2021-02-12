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
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.Rfc;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class IdTokenBuilderTest {

    private static final String uriIdpServer = "https://idp.zentral.idp.splitdns.ti-dienste.de";
    private static final long maxIdTokenExpirationInSec = 86400;
    private IdTokenBuilder idTokenBuilder;
    private JsonWebToken authenticationToken;

    @BeforeEach
    public void init(@PkiKeyResolver.Filename("authz_rsa") final PkiIdentity clientIdentity) {
        final Map<String, Object> bodyClaims = new HashMap<>();
        bodyClaims.put(PROFESSION_OID.getJoseName(), "profession");
        bodyClaims.put(ORGANIZATION_NAME.getJoseName(), "organization");
        bodyClaims.put(ID_NUMBER.getJoseName(), "id_number");
        bodyClaims.put(GIVEN_NAME.getJoseName(), "given_name");
        bodyClaims.put(FAMILY_NAME.getJoseName(), "family_name");
        bodyClaims.put(JWKS_URI.getJoseName(), "jwks_uri");
        bodyClaims.put(CLIENT_ID.getJoseName(), IdpConstants.CLIENT_ID);
        authenticationToken = new JwtBuilder()
            .replaceAllHeaderClaims(Map.of("headerNotCopy", "headerNotCopy"))
            .replaceAllBodyClaims(bodyClaims)
            .setSignerKey(clientIdentity.getPrivateKey())
            .buildJwt();
        idTokenBuilder = new IdTokenBuilder(new IdpJwtProcessor(clientIdentity), uriIdpServer, "saltValue");
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 2 ID Token")
    @Afo("A_20313")
    @Afo("TODO A_20297/ML-110385?")
    @Test
    public void checkIdTokenClaims() {
        final JsonWebToken idToken = idTokenBuilder
            .buildIdToken(IdpConstants.CLIENT_ID, authenticationToken, "fdsjkfldsöaf".getBytes(
                StandardCharsets.UTF_8));

        assertThat(idToken.getBodyClaims())
            .containsEntry(ISSUER.getJoseName(), uriIdpServer)
            .containsKey(SUBJECT.getJoseName())
            .containsEntry(AUDIENCE.getJoseName(), IdpConstants.CLIENT_ID)
            .containsKey(EXPIRES_AT.getJoseName())
            .containsKey(ISSUED_AT.getJoseName())
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
        final JsonWebToken idToken = idTokenBuilder
            .buildIdToken(IdpConstants.CLIENT_ID, authenticationToken, "fdsjkfldsöaf".getBytes(
                StandardCharsets.UTF_8));

        final long now = ZonedDateTime.now().toEpochSecond();
        final long expHeader = idToken.getExpiresAt().toEpochSecond();
        final long expBody = idToken.getExpiresAtBody().toEpochSecond();
        final long iat = idToken.getIssuedAt().toEpochSecond();

        assertThat(now).isGreaterThanOrEqualTo(iat);
        assertThat(now).isLessThan(expHeader);
        assertThat(now).isLessThan(expBody);
        assertThat(expHeader - now).isLessThan(maxIdTokenExpirationInSec);
    }

    @Rfc("OpenID Connect Core 1.0 - 3.1.3.6.")
    @Test
    public void checkIdTokenClaimAtHash() {
        final byte[] accesTokenHash = DigestUtils.sha256("fdsjkfldsöaf");
        final JsonWebToken idToken = idTokenBuilder
            .buildIdToken(IdpConstants.CLIENT_ID, authenticationToken, accesTokenHash);

        assertThat(Base64.getDecoder().decode(idToken.getStringBodyClaim(ACCESS_TOKEN_HASH).get()))
            .isEqualTo(ArrayUtils.subarray(accesTokenHash, 0, (128 / 8)))
            .hasSize(128 / 8);
    }
}
