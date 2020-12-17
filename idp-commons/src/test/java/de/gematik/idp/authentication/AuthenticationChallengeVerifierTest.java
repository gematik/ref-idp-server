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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.TokenClaimExtraction;
import java.util.Map;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
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

    @BeforeEach
    public void init(
        @PkiKeyResolver.Filename("hsm_ecc") final PkiIdentity serverIdentity,
        @PkiKeyResolver.Filename("aut-ecc") final PkiIdentity clientIdentity) {
        this.clientIdentity = clientIdentity;

        authenticationChallengeBuilder = AuthenticationChallengeBuilder.builder()
            .authenticationIdentity(serverIdentity)
            .build();
        authenticationResponseBuilder = AuthenticationResponseBuilder.builder()
            .build();
        authenticationChallengeVerifier = AuthenticationChallengeVerifier.builder()
            .serverIdentity(serverIdentity)
            .build();
        authenticationChallenge = authenticationChallengeBuilder
            .buildAuthenticationChallenge("goo", "foo", "bar", "schmar");
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

        final Map<String, Object> nestedClaims = TokenClaimExtraction.extractClaimsFromTokenBody(
            authenticationResponse.getSignedChallenge().getStringBodyClaim(ClaimName.NESTED_JWT.getJoseName()).get());
        assertThat(nestedClaims)
            .containsEntry("client_id", "goo")
            .containsEntry("state", "foo")
            .containsEntry("redirect_uri", "bar")
            .containsEntry("code_challenge", "schmar");
    }

    private String rebuildChallengeResponseString(final Object njwt, final PkiIdentity signerIdentity) {
        final JwtClaims claims = new JwtClaims();
        claims.setClaim("njwt", njwt);
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claims.toJson());
        jsonWebSignature.setAlgorithmHeaderValue(BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256);
        jsonWebSignature.setKey(signerIdentity.getPrivateKey());

        jsonWebSignature.setHeader("typ", "jwt");
        jsonWebSignature.setHeader("cty", "njwt");
        jsonWebSignature.setCertificateChainHeaderValue(signerIdentity.getCertificate());

        try {
            return jsonWebSignature.getCompactSerialization();
        } catch (final JoseException e) {
            throw new RuntimeException(e);
        }

    }
}
