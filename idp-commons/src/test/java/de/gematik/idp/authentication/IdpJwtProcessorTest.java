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

package de.gematik.idp.authentication;

import static de.gematik.idp.field.ClaimName.*;
import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
class IdpJwtProcessorTest {

    static {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    static final long TOKEN_VALIDITY_MINUTES = 10;
    JwtBuilder jwtBuilder = new JwtBuilder()
        .expiresAt(ZonedDateTime.now().plusMinutes(10))
        .addAllBodyClaims(new HashMap<>(Map.ofEntries(
            entry(ISSUED_AT.getJoseName(), ZonedDateTime.now().toEpochSecond()),
            entry(ISSUER.getJoseName(), "https://idp.zentral.idp.splitdns.ti-dienste.de"),
            entry(RESPONSE_TYPE.getJoseName(), "code"),
            entry(SCOPE.getJoseName(), "openid e-rezept"),
            entry(CLIENT_ID.getJoseName(), "ZXJlemVwdC1hcHA"),
            entry(STATE.getJoseName(), "af0ifjsldkj"),
            entry(REDIRECT_URI.getJoseName(), "https://app.e-rezept.com/authnres"),
            entry(JWT_ID.getJoseName(), "c3a8f9c8-aa62-11ea-ac15-6b7a3355d0f6"),
            entry(CODE_CHALLENGE_METHOD.getJoseName(), "S256"),
            entry(CODE_CHALLENGE.getJoseName(), "S41HgHxhXL1CIpfGvivWYpbO9b_QKzva-9ImuZbt0Is")
        )))

        .addAllHeaderClaims(new HashMap<>(Map.ofEntries(
            // two parts of header are written by library: ("typ", "JWT"),("alg", "ES256")
            entry(SERVER_NONCE.getJoseName(), "sLlxlkskAyuzdDOwe8nZeeQVFBWgscNkRcpgHmKidFc"),
            entry(EXPIRES_AT.getJoseName(),
                LocalDateTime.now().plusMinutes(TOKEN_VALIDITY_MINUTES).toEpochSecond(ZoneOffset.UTC))
        )));

    private IdpJwtProcessor jwtProcessor;

    {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void build_rsa(final PkiIdentity rsa) {
        final JsonWebToken jwt = createJwt(rsa);
        jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
    }

    @Test
    void build_ecc(final PkiIdentity ecc) {
        final JsonWebToken jwt = createJwt(ecc);
        jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
    }

    @Test
    void verifyInvalidHeader_ecc(final PkiIdentity ecc) {
        final JsonWebToken jwt = createJwt(ecc);
        jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
        // delete first character
        final String jwtJasonInvalid = jwt.getRawString().substring(1);
        JsonWebToken jsonWebToken = new JsonWebToken(jwtJasonInvalid);
        assertThatThrownBy(() -> jwtProcessor.verifyAndThrowExceptionIfFail(jsonWebToken))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    void verifyInvalidSignature_ecc(final PkiIdentity ecc) {
        final JsonWebToken jwt = createJwt(ecc);
        // delete last character
        final String jwtJasonInvalid = jwt.getRawString().substring(0, jwt.getRawString().length() - 1);
        JsonWebToken jsonWebToken = new JsonWebToken(jwtJasonInvalid);
        assertThat(jsonWebToken).isNotNull();
        assertThatThrownBy(() -> jwtProcessor.verifyAndThrowExceptionIfFail(jsonWebToken))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    void verifySignAlgo_ecc(final PkiIdentity ecc) {
        final JsonWebToken jwt = createJwt(ecc);
        jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
        assertThat(jwtProcessor.getHeaderDecoded(jwt))
            .contains(BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256);
        assertThat(jwtProcessor.getHeaderDecoded(jwt)).doesNotContain("RS256");
    }

    @Test
    void verifyHeaderElementsComplete_ecc(final PkiIdentity ecc) {
        final JsonWebToken jwt = createJwt(ecc);
        jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
        assertThat(jwtProcessor.getHeaderDecoded(jwt))
            .contains(ALGORITHM.getJoseName());
    }

    @Test
    void verifyPayloadElementsComplete_ecc(final PkiIdentity ecc) {
        final JsonWebToken jwt = createJwt(ecc);
        jwtProcessor.verifyAndThrowExceptionIfFail(jwt);
        final String payloadAsString = jwtProcessor.getPayloadDecoded(jwt);
        assertThat(payloadAsString)
            .contains(RESPONSE_TYPE.getJoseName())
            .contains(SCOPE.getJoseName())
            .contains(CLIENT_ID.getJoseName())
            .contains(STATE.getJoseName())
            .contains(REDIRECT_URI.getJoseName())
            .contains(CODE_CHALLENGE_METHOD.getJoseName())
            .contains(CODE_CHALLENGE.getJoseName())
            .contains(EXPIRES_AT.getJoseName());
    }

    @Test
    void verifyPayloadMeetsJwtDescription_ecc(final PkiIdentity ecc) {
        final JsonWebToken jwtAsBase64 = createJwt(ecc);
        jwtProcessor.verifyAndThrowExceptionIfFail(jwtAsBase64);
        final String payloadAsString = jwtProcessor.getPayloadDecoded(jwtAsBase64);
        jwtBuilder.getClaims().forEach((key, value) -> assertThat(payloadAsString).contains(key));
        jwtBuilder.getClaims().forEach((key, value) -> assertThat(payloadAsString).contains(value.toString()));
    }

    private JsonWebToken createJwt(final PkiIdentity identity) {
        jwtProcessor = new IdpJwtProcessor(identity);
        return jwtProcessor.buildJwt(jwtBuilder);
    }
}
