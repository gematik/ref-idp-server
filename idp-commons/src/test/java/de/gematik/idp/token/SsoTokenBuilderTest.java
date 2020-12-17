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

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.time.ZonedDateTime;

import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CONFIRMATION;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(PkiKeyResolver.class)
public class SsoTokenBuilderTest {

    private PkiIdentity serverIdentity;
    private PkiIdentity clientIdentity;
    private SsoTokenBuilder ssoTokenBuilder;

    @BeforeEach
    public void init(final PkiIdentity ecc,
                     @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity) {
        serverIdentity = ecc;
        this.clientIdentity = clientIdentity;
        final IdpJwtProcessor serverJwtProcessor = new IdpJwtProcessor(serverIdentity);
        ssoTokenBuilder = new SsoTokenBuilder(serverJwtProcessor);
    }

    @Test
    public void ssoTokenShouldContainCnf() {
        final JsonWebToken ssoToken = ssoTokenBuilder
                .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now());

        assertThat(ssoToken.getBodyClaims())
                .containsKey(ClaimName.CONFIRMATION.getJoseName());
    }

    @Test
    public void ssoTokenShouldContainValidClaims() {
        final JsonWebToken ssoToken = ssoTokenBuilder
                .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now());

        assertThat(ssoToken.getHeaderClaims())
                .containsKeys(
                        ClaimName.ALGORITHM.getJoseName(),
                        ClaimName.TYPE.getJoseName(),
                        ClaimName.JWT_ID.getJoseName());

        assertThat(ssoToken.getBodyClaims())
                .containsKeys(
                        ClaimName.ISSUER.getJoseName(),
                        ClaimName.ISSUED_AT.getJoseName(),
                        ClaimName.NOT_BEFORE.getJoseName(),
                        ClaimName.EXPIRES_AT.getJoseName(),
                        ClaimName.GIVEN_NAME.getJoseName(),
                        ClaimName.FAMILY_NAME.getJoseName(),
                        ClaimName.ORGANIZATION_NAME.getJoseName(),
                        ClaimName.PROFESSION_OID.getJoseName(),
                        ClaimName.ID_NUMBER.getJoseName());
    }

    @Afo("A_20731")
    @Test
    public void verifyAuthTime() {
        final JsonWebToken ssoToken = ssoTokenBuilder
                .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now());
        assertThat(ssoToken.getDateTimeBodyClaim(AUTH_TIME.getJoseName()).get())
                .isBetween(ZonedDateTime.now().minusSeconds(5), ZonedDateTime.now());
    }

    @Test
    public void verifyCnfDoesNotContainNullValues() {
        final JsonWebToken ssoToken = ssoTokenBuilder
                .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now());

        assertThat(ssoToken.getBodyClaim(CONFIRMATION).get().toString())
                .doesNotContain("null");
    }
}
