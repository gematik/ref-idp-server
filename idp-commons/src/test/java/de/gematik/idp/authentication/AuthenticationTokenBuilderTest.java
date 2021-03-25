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

package de.gematik.idp.authentication;

import static de.gematik.idp.field.ClaimName.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import de.gematik.idp.token.JsonWebToken;
import java.time.ZonedDateTime;
import java.util.Collections;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class AuthenticationTokenBuilderTest {

    private AuthenticationTokenBuilder authenticationTokenBuilder;
    private PkiIdentity clientIdentity;
    private SecretKeySpec encryptionKey;

    @BeforeEach
    public void init(final PkiIdentity ecc,
        @Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity) {

        encryptionKey = new SecretKeySpec(DigestUtils.sha256("fdsa"), "AES");
        authenticationTokenBuilder = AuthenticationTokenBuilder.builder()
            .jwtProcessor(new IdpJwtProcessor(ecc))
            .authenticationChallengeVerifier(mock(AuthenticationChallengeVerifier.class))
            .encryptionKey(encryptionKey)
            .build();

        this.clientIdentity = clientIdentity;
    }

    @Test
    public void extractClaimsFromClientCertificateTest() {
        Assertions.assertThat(authenticationTokenBuilder
            .buildAuthenticationToken(clientIdentity.getCertificate(), Collections.emptyMap(),
                ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey)
            .getBodyClaims())
            .containsEntry(PROFESSION_OID.getJoseName(), "1.2.276.0.76.4.49")
            .containsEntry(GIVEN_NAME.getJoseName(), "Juna")
            .containsEntry(FAMILY_NAME.getJoseName(), "Fuchs");
    }

    @Afo("A_20526")
    @Test
    public void testAuthenticationTokenHeaderHasType() {
        final JsonWebToken authenticationToken = authenticationTokenBuilder
            .buildAuthenticationToken(clientIdentity.getCertificate(), Collections.emptyMap(), ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey);

        assertThat(authenticationToken.getHeaderClaims())
            .containsEntry(TYPE.getJoseName(), "JWT");
    }

    @Afo("A_20731")
    @Test
    public void testAuthenticationTokenHasAuthTime() {
        final ZonedDateTime now = ZonedDateTime.now();
        final JsonWebToken authenticationToken = authenticationTokenBuilder
            .buildAuthenticationToken(clientIdentity.getCertificate(), Collections.emptyMap(), now)
            .decryptNestedJwt(encryptionKey);

        assertThat(authenticationToken.getBodyClaims())
            .extractingByKey(AUTH_TIME.getJoseName())
            .extracting(Long.class::cast)
            .isEqualTo(now.toEpochSecond());
    }

    @Test
    public void verifyThatAuthenticationTokenCarriesIatClaimOnlyInBody() {
        final ZonedDateTime now = ZonedDateTime.now();
        final JsonWebToken authenticationToken = authenticationTokenBuilder
            .buildAuthenticationToken(clientIdentity.getCertificate(), Collections.emptyMap(), now)
            .decryptNestedJwt(encryptionKey);

        assertThat(authenticationToken.getHeaderClaims())
            .as("Authentication-Token Header-Claims")
            .doesNotContainKey(ISSUED_AT.getJoseName());
        assertThat(authenticationToken.getBodyClaims())
            .as("Authentication-Token Body-Claims")
            .containsKey(ISSUED_AT.getJoseName());
    }

    @Test
    public void verifyThatAuthenticationTokenCarriesExpClaimInBodyAndHeader() {
        final ZonedDateTime now = ZonedDateTime.now();
        final JsonWebToken authenticationToken = authenticationTokenBuilder
            .buildAuthenticationToken(clientIdentity.getCertificate(), Collections.emptyMap(), now)
            .decryptNestedJwt(encryptionKey);

        assertThat(authenticationToken.getHeaderClaims())
            .as("Authentication-Token exp in Header-Claims")
            .doesNotContainKey(EXPIRES_AT.getJoseName());
        assertThat(authenticationToken.getBodyClaims())
            .as("Authentication-Token exp in Body-Claims")
            .containsKey(EXPIRES_AT.getJoseName());
    }

    @Test
    public void authenticationTokenShouldBeValidForOneMinute() {
        final ZonedDateTime now = ZonedDateTime.now();
        final JsonWebToken authenticationToken = authenticationTokenBuilder
            .buildAuthenticationToken(clientIdentity.getCertificate(), Collections.emptyMap(), now)
            .decryptNestedJwt(encryptionKey);

        assertThat(authenticationToken.getExpiresAt())
            .isEqualToIgnoringNanos(now.plusMinutes(1));
    }
}
