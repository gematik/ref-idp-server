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

package de.gematik.idp.authentication;

import static de.gematik.idp.field.ClaimName.*;
import static org.assertj.core.api.Assertions.*;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.Remark;
import de.gematik.idp.tests.Rfc;
import de.gematik.idp.token.TokenClaimExtraction;
import java.time.ZonedDateTime;
import java.util.Map;
import org.bouncycastle.util.encoders.Base64;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class AuthenticationChallengeBuilderTest {

    private static final long CHALLENGE_TOKEN_VALIDITY_IN_MINUTES = 5;
    private AuthenticationChallengeBuilder authenticationChallengeBuilder;
    private JwtConsumer jwtConsumer;

    @BeforeEach
    public void init(@PkiKeyResolver.Filename("rsa") final PkiIdentity serverIdentity) {
        authenticationChallengeBuilder = AuthenticationChallengeBuilder.builder()
            .authenticationIdentity(serverIdentity)
            .build();

        jwtConsumer = new JwtConsumerBuilder()
            .setVerificationKey(serverIdentity.getCertificate().getPublicKey())
            .setSkipDefaultAudienceValidation()
            .build();
    }

    @Test
    public void authenticationChallengeTest() {
        assertThat(authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar"))
            .isNotNull();
    }

    @Test
    public void challengeAttributeIsJwtAndSignedByCertificate(
        @PkiKeyResolver.Filename("rsa") final PkiIdentity serverIdentity) throws InvalidJwtException {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");

        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setVerificationKey(serverIdentity.getCertificate().getPublicKey())
            .setSkipDefaultAudienceValidation()
            .build();

        jwtConsumer.process(response.getChallenge());
        assertThat(response.getChallenge())
            .isNotNull();
    }

    @Test
    public void challengeWithClaims() throws InvalidJwtException {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");

        final JwtContext jwtContext = jwtConsumer.process(response.getChallenge());
        assertThat(jwtContext.getJwtClaims().getClaimNames())
            .contains(CODE_CHALLENGE_METHOD.getJoseName());
        assertThat(jwtContext.getJwtClaims().getClaimValue(CODE_CHALLENGE_METHOD.getJoseName()))
            .isEqualTo("S256");
    }

    @Test
    @Remark("Ticket IDP-93: Server Nonce 256 bits == 32 bytes")
    public void challengeHeaderClaimItemSnc() {
        final int SNC_NONCE_BYTE_AMOUNT = 32;
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");

        final Map<String, Object> headerClaims = TokenClaimExtraction
            .extractClaimsFromTokenHeader(response.getChallenge());
        final String snc = headerClaims.get(NONCE.getJoseName()).toString();
        assertThat(Base64.decode(snc)).hasSize(SNC_NONCE_BYTE_AMOUNT);
    }

    @Test
    @Remark("Ticket IDP-93: typ == JWT")
    public void challengeHeaderClaimItemTyp() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");

        assertThat(TokenClaimExtraction.extractClaimsFromTokenHeader(response.getChallenge()))
            .hasFieldOrPropertyWithValue(TYPE.getJoseName(), "JWT");
    }

    @Test
    @Remark("Ticket IDP-93: exp == 5min")
    @Rfc("7519 4.1.4.  \"exp\" (Expiration Time) Claim")
    public void challengeHeaderClaimItemExp() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");

        final Map<String, Object> bodyClaims = TokenClaimExtraction
            .extractClaimsFromTokenBody(response.getChallenge());

        assertThat(TokenClaimExtraction.claimToDateTime(bodyClaims.get(EXPIRES_AT.getJoseName())))
            .isBetween(ZonedDateTime.now().plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES).minusSeconds(5),
                ZonedDateTime.now().plusMinutes(CHALLENGE_TOKEN_VALIDITY_IN_MINUTES));
    }

    @Test
    @Rfc("7519 4.1.6.  \"iat\" (Issued At) Claim")
    public void challengeHeaderClaimItemIat() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");

        final Map<String, Object> bodyClaims = TokenClaimExtraction
            .extractClaimsFromTokenBody(response.getChallenge());
        assertThat(TokenClaimExtraction.claimToDateTime(bodyClaims.get(ISSUED_AT.getJoseName())))
            .isBetween(ZonedDateTime.now().minusSeconds(5), ZonedDateTime.now());
    }

    @Test
    @Remark("Ticket IDP-93: \"jti\" string length: 8-64")
    @Rfc("7519 4.1.7.  \"jti\" (JWT ID) Claim")
    public void challengeHeaderClaimItemJti() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");

        assertThat(TokenClaimExtraction.extractClaimsFromTokenHeader(response.getChallenge())).as("headerClaims").
            extracting(JWT_ID.getJoseName()).asString().hasSizeBetween(16, 64);
    }

    @Test
    @Rfc("7519 4.1.5.  \"nbf\" (Not Before) Claim")
    public void challengeHeaderClaimItemNbf() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");

        final Map<String, Object> bodyClaims = TokenClaimExtraction
            .extractClaimsFromTokenBody(response.getChallenge());

        final ZonedDateTime tokenNotBefore = TokenClaimExtraction
            .claimToDateTime(bodyClaims.get(NOT_BEFORE.getJoseName()));
        assertThat(tokenNotBefore).isBetween(ZonedDateTime.now().minusSeconds(10), ZonedDateTime.now());
    }

    @Test
    @Afo("A_20440")
    public void challengeWithConsent() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");
        assertThat(response.getUserConsent()).isNotNull();
        assertThat(response.getUserConsent()).hasSize(5);
        assertThat(response.getUserConsent())
            .containsExactlyInAnyOrder(GIVEN_NAME, FAMILY_NAME, ORGANIZATION_NAME, PROFESSION_OID, ID_NUMBER);
    }


    @Test
    public void verifyThatAuthenticationChallengeCarriesExpIatNbfClaimNotInHeader() {
        final AuthenticationChallenge response = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");
        final Map<String, Object> headerClaims = TokenClaimExtraction
            .extractClaimsFromTokenHeader(response.getChallenge());
        assertThat(headerClaims)
            .doesNotContainKeys(EXPIRES_AT.getJoseName())
            .doesNotContainKeys(NOT_BEFORE.getJoseName())
            .doesNotContainKeys(ISSUED_AT.getJoseName());
    }

}
