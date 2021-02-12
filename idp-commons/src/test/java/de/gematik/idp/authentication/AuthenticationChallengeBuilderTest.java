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
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.Remark;
import de.gematik.idp.tests.Rfc;
import java.time.ZonedDateTime;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class AuthenticationChallengeBuilderTest {

    private static final long CHALLENGE_TOKEN_VALIDITY_IN_MINUTES = 3;
    private AuthenticationChallengeBuilder authenticationChallengeBuilder;

    @BeforeEach
    public void init(@PkiKeyResolver.Filename("rsa") final PkiIdentity serverIdentity) {
        authenticationChallengeBuilder = AuthenticationChallengeBuilder.builder()
            .authenticationIdentity(serverIdentity)
            .build();
    }

    @Test
    public void authenticationChallengeTest() {
        assertThat(authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue"))
            .isNotNull();
    }

    @Test
    public void challengeAttributeIsJwtAndSignedByCertificate(
        @PkiKeyResolver.Filename("rsa") final PkiIdentity serverIdentity) throws InvalidJwtException {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue");

        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setVerificationKey(serverIdentity.getCertificate().getPublicKey())
            .setSkipDefaultAudienceValidation()
            .build();

        jwtConsumer.process(response.getChallenge().getRawString());
        assertThat(response.getChallenge())
            .isNotNull();
    }

    @Test
    public void challengeWithClaims() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue");

        assertThat(response.getChallenge().getBodyClaims())
            .containsEntry(CODE_CHALLENGE_METHOD.getJoseName(), "S256");
    }

    @Test
    @Remark("Ticket IDP-93: typ == JWT")
    public void challengeHeaderClaimItemTyp() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue");

        assertThat(response.getChallenge().getHeaderClaims())
            .containsEntry(TYPE.getJoseName(), "JWT");
    }

    @Test
    @Remark("Ticket IDP-93: typ == JWT")
    public void challengeBodyTokenType() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue");

        assertThat(response.getChallenge().getBodyClaim(TOKEN_TYPE))
            .get().asString()
            .isEqualTo("challenge");
    }

    @Test
    @Remark("Ticket IDP-93: exp == 5min")
    @Rfc("7519 4.1.4.  \"exp\" (Expiration Time) Claim")
    public void challengeBodyClaimItemExp() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue");

        assertThat(response.getChallenge().getExpiresAt())
            .isBetween(ZonedDateTime.now().plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES).minusSeconds(5),
                ZonedDateTime.now().plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES));
    }

    @Test
    @Rfc("7519 4.1.6.  \"iat\" (Issued At) Claim")
    public void challengeBodyClaimItemIat() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue");

        assertThat(response.getChallenge().getBodyDateTimeClaim(ISSUED_AT).get())
            .isBetween(ZonedDateTime.now().minusSeconds(5), ZonedDateTime.now());
    }

    @Test
    @Remark("Ticket IDP-93: \"jti\" string length: 8-64")
    @Rfc("7519 4.1.7.  \"jti\" (JWT ID) Claim")
    public void challengeBodyClaimItemJti() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue");

        assertThat(response.getChallenge().getBodyClaim(JWT_ID).get())
            .asString()
            .hasSizeBetween(16, 64);
    }

    @Test
    @Afo("A_20440")
    public void challengeWithConsent() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue");
        assertThat(response.getUserConsent()).isNotNull();
        assertThat(response.getUserConsent()).hasSize(5);
        assertThat(response.getUserConsent())
            .containsExactlyInAnyOrder(GIVEN_NAME, FAMILY_NAME, ORGANIZATION_NAME, PROFESSION_OID, ID_NUMBER);
    }


    @Test
    public void verifyThatAuthenticationChallengeCarriesExpButNotIatNbfClaimInHeader() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid", "nonceValue");
        assertThat(response.getChallenge().getHeaderClaims().keySet())
            .contains(EXPIRES_AT.getJoseName())
            .doesNotContain(NOT_BEFORE.getJoseName(), ISSUED_AT.getJoseName());
    }
}
