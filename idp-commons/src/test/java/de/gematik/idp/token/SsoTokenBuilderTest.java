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

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import java.time.ZonedDateTime;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class SsoTokenBuilderTest {

    private static final String uriIdpServer = "https://idp.zentral.idp.splitdns.ti-dienste.de";
    private PkiIdentity serverIdentity;
    private PkiIdentity clientIdentity;
    private SsoTokenBuilder ssoTokenBuilder;
    private SecretKeySpec encryptionKey;

    @BeforeEach
    public void init(final PkiIdentity ecc,
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity) {
        serverIdentity = ecc;
        this.clientIdentity = clientIdentity;
        final IdpJwtProcessor serverJwtProcessor = new IdpJwtProcessor(serverIdentity);
        encryptionKey = new SecretKeySpec(DigestUtils.sha256("fdsfdsafdsafdsafdsarvdfvcxyvcxyvc".getBytes()), "AES");
        ssoTokenBuilder = new SsoTokenBuilder(serverJwtProcessor, uriIdpServer,
            encryptionKey);
    }

    @Test
    public void ssoTokenShouldContainCnf() {
        final JsonWebToken ssoToken = ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey);

        assertThat(ssoToken.getBodyClaims())
            .containsKey(ClaimName.CONFIRMATION.getJoseName());
    }

    @Test
    public void ssoTokenShouldContainValidClaims() {
        final JsonWebToken ssoToken = ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey);

        assertThat(ssoToken.getHeaderClaims())
            .containsKeys(
                ALGORITHM.getJoseName(),
                TYPE.getJoseName());

        assertThat(ssoToken.getBodyClaims())
            .containsKeys(
                ISSUED_AT.getJoseName(),
                NOT_BEFORE.getJoseName(),
                EXPIRES_AT.getJoseName(),
                GIVEN_NAME.getJoseName(),
                FAMILY_NAME.getJoseName(),
                ORGANIZATION_NAME.getJoseName(),
                PROFESSION_OID.getJoseName(),
                ID_NUMBER.getJoseName())
            .containsEntry(ISSUER.getJoseName(), uriIdpServer);
    }

    @Afo("A_20731")
    @Test
    public void verifyAuthTime() {
        final JsonWebToken ssoToken = ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey);

        assertThat(ssoToken.getDateTimeClaim(AUTH_TIME, () -> ssoToken.getBodyClaims()).get())
            .isBetween(ZonedDateTime.now().minusSeconds(5), ZonedDateTime.now());
    }

    @Test
    public void verifyExpClaim() {
        final JsonWebToken ssoToken = ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey);

        assertThat(ssoToken.getBodyDateTimeClaim(EXPIRES_AT).get())
            .isBetween(ZonedDateTime.now().plusHours(12).minusSeconds(10), ZonedDateTime.now().plusHours(12));
    }

    @Test
    public void verifyCnfDoesNotContainNullValues() {
        final JsonWebToken ssoToken = ssoTokenBuilder
            .buildSsoToken(clientIdentity.getCertificate(), ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey);

        assertThat(ssoToken.getBodyClaim(CONFIRMATION).get().toString())
            .doesNotContain("null");
    }
}
