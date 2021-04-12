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

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.data.UserConsentDescriptionTexts;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.time.ZonedDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class AuthenticationChallengeVerifierTest {

    private AuthenticationChallenge authenticationChallenge;
    private AuthenticationChallengeBuilder authenticationChallengeBuilder;
    private AuthenticationResponseBuilder authenticationResponseBuilder;
    private AuthenticationChallengeVerifier authenticationChallengeVerifier;
    private PkiIdentity clientIdentity;
    private PkiIdentity serverIdentity;
    private Map<String, Map<String, String>> userConsentConfiguration;

    @BeforeEach
    public void init(
        @PkiKeyResolver.Filename("1_C.SGD-HSM.AUT_oid_sgd1_hsm_ecc.p12") final PkiIdentity serverIdentity,
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc.p12") final PkiIdentity clientIdentity) {
        this.clientIdentity = clientIdentity;
        this.serverIdentity = serverIdentity;
        authenticationChallengeBuilder = AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(serverIdentity))
            .userConsentConfiguration(UserConsentConfiguration.builder()
                .claimsToBeIncluded(Map.of(IdpScope.OPENID, List.of(),
                    IdpScope.EREZEPT, List.of(),
                    IdpScope.PAIRING, List.of()))
                .descriptionTexts(UserConsentDescriptionTexts.builder()
                    .claims(Collections.emptyMap())
                    .scopes(Map.of(IdpScope.OPENID, "openid",
                        IdpScope.PAIRING, "pairing",
                        IdpScope.EREZEPT, "erezept"))
                    .build())
                .build())
            .build();
        authenticationResponseBuilder = AuthenticationResponseBuilder.builder()
            .build();
        authenticationChallengeVerifier = AuthenticationChallengeVerifier.builder()
            .serverIdentity(serverIdentity)
            .build();
        authenticationChallenge = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid pairing", "nonceValue");
    }

    @Test
    public void verifyEmptyResponse_shouldGiveException() {
        assertThatThrownBy(() -> authenticationChallengeVerifier.verifyResponseAndThrowExceptionIfFail(null))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    public void verifyCorrectResponse_shouldPass() {
        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(authenticationChallenge,
                clientIdentity);
        authenticationChallengeVerifier
            .verifyResponseAndThrowExceptionIfFail(authenticationResponse.getSignedChallenge());
    }

    @Test
    public void extractClaims_shouldBePresent() {
        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(authenticationChallenge,
                clientIdentity);

        Assertions.assertThat(authenticationResponse.getSignedChallenge().getStringBodyClaim(ClaimName.NESTED_JWT)
            .map(Objects::toString)
            .map(JsonWebToken::new)
            .map(JsonWebToken::getBodyClaims).get())
            .containsEntry("client_id", "goo")
            .containsEntry("state", "foo")
            .containsEntry("redirect_uri", "bar")
            .containsEntry("code_challenge", "schmar");
    }

    @Test
    public void checkSignatureNjwt_certMismatch(
        @PkiKeyResolver.Filename("833621999741600_c.hci.aut-apo-ecc.p12") final PkiIdentity otherServerIdentity) {
        authenticationChallengeBuilder = AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(otherServerIdentity))
            .userConsentConfiguration(UserConsentConfiguration.builder()
                .claimsToBeIncluded(Map.of(IdpScope.OPENID, List.of(),
                    IdpScope.EREZEPT, List.of(),
                    IdpScope.PAIRING, List.of()))
                .descriptionTexts(UserConsentDescriptionTexts.builder()
                    .claims(Collections.emptyMap())
                    .scopes(Map.of(IdpScope.OPENID, "openid",
                        IdpScope.PAIRING, "pairing",
                        IdpScope.EREZEPT, "erezept"))
                    .build())
                .build())
            .build();
        authenticationChallenge = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue");

        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(authenticationChallenge,
                clientIdentity);

        assertThatThrownBy(() -> authenticationChallengeVerifier
            .verifyResponseAndThrowExceptionIfFail(authenticationResponse.getSignedChallenge()))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    public void checkSignatureNjwt_invalidChallenge() {
        final AuthenticationChallenge ch = AuthenticationChallenge.builder()
            .challenge(new JsonWebToken("SicherNichtDerRichtigeChallengeCode"))
            .build();
        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(ch,
                clientIdentity);
        assertThatThrownBy(() -> authenticationChallengeVerifier
            .verifyResponseAndThrowExceptionIfFail(authenticationResponse.getSignedChallenge()))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    public void checkSignatureNjwt_challengeOutdated() {
        authenticationChallenge = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar", IdpScope.EREZEPT.getJwtValue(), "nonceValue");
        final JsonWebToken jsonWebToken = authenticationChallenge.getChallenge();
        final IdpJwtProcessor reSignerProcessor = new IdpJwtProcessor(serverIdentity);
        final JwtBuilder jwtDescription = jsonWebToken.toJwtDescription();
        jwtDescription.expiresAt(ZonedDateTime.now().minusSeconds(1));
        authenticationChallenge.setChallenge(reSignerProcessor.buildJwt(jwtDescription));

        final AuthenticationResponse authenticationResponse =
            authenticationResponseBuilder.buildResponseForChallenge(authenticationChallenge,
                clientIdentity);

        assertThatThrownBy(() -> authenticationChallengeVerifier
            .verifyResponseAndThrowExceptionIfFail(authenticationResponse.getSignedChallenge()))
            .isInstanceOf(RuntimeException.class);
    }
}
