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

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.field.ClaimName.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.TestConstants;
import de.gematik.idp.authentication.AuthenticationChallengeVerifier;
import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.RequiredClaimException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Optional;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.digest.DigestUtils;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class AccessTokenBuilderTest {

    private final static String URI_IDP_SERVER = "https://idp.zentral.idp.splitdns.ti-dienste.de";
    private static final String KEY_ID = "my_key_id";

    private AccessTokenBuilder accessTokenBuilder;
    private IdpJwtProcessor serverTokenProcessor;
    private JsonWebToken authenticationToken;
    private SecretKeySpec encryptionKey;

    @BeforeEach
    public void init(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity,
        @PkiKeyResolver.Filename("ecc") final PkiIdentity serverIdentity) {
        serverIdentity.setKeyId(Optional.of(KEY_ID));
        serverTokenProcessor = new IdpJwtProcessor(serverIdentity);
        accessTokenBuilder = new AccessTokenBuilder(serverTokenProcessor, URI_IDP_SERVER, "saltValue");
        encryptionKey = new SecretKeySpec(DigestUtils.sha256("fdsa"), "AES");
        final AuthenticationTokenBuilder authenticationTokenBuilder = AuthenticationTokenBuilder.builder()
            .jwtProcessor(serverTokenProcessor)
            .authenticationChallengeVerifier(mock(AuthenticationChallengeVerifier.class))
            .encryptionKey(encryptionKey)
            .build();
        authenticationToken = authenticationTokenBuilder
            .buildAuthenticationToken(clientIdentity.getCertificate(),
                Map.of("acr", "foobar", CLIENT_ID.getJoseName(), TestConstants.CLIENT_ID_E_REZEPT_APP),
                ZonedDateTime.now())
            .decryptNestedJwt(encryptionKey);
    }

    @Afo("A_20524")
    @Test
    public void requiredFieldMissingFromAuthenticationToken_ShouldThrowRequiredClaimException() {
        assertThatThrownBy(
            () -> accessTokenBuilder.buildAccessToken(serverTokenProcessor.buildJwt(new JwtBuilder()
                .addAllBodyClaims(Map.of(PROFESSION_OID.getJoseName(), "foo"))
                .expiresAt(ZonedDateTime.now().plusMinutes(100)))))
            .isInstanceOf(RequiredClaimException.class)
            .hasMessageContaining(ID_NUMBER.getJoseName());
    }

    @Afo("A_20524")
    @Test
    public void verifyThatAllRequiredClaimsAreInBody() {
        final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);

        assertThat(accessToken.getBodyClaims())
            .containsEntry(GIVEN_NAME.getJoseName(), "Juna")
            .containsEntry(FAMILY_NAME.getJoseName(), "Fuchs")
            .containsEntry(ORGANIZATION_NAME.getJoseName(), "gematik GmbH NOT-VALID")
            .containsEntry(PROFESSION_OID.getJoseName(), "1.2.276.0.76.4.49")
            .containsEntry(ID_NUMBER.getJoseName(), "X114428530")
            .containsEntry(ISSUER.getJoseName(), URI_IDP_SERVER)
            .containsEntry(AUDIENCE.getJoseName(), IdpConstants.AUDIENCE)
            .containsKey(ISSUED_AT.getJoseName())
            .containsKey(AUTH_TIME.getJoseName());
    }

    @Test
    public void verifyThatAllRequiredClaimsAreInHeader() {
        final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
        assertThat(accessToken.getHeaderClaims())
            .containsEntry(ClaimName.KEY_ID.getJoseName(), KEY_ID);
    }

    @Test
    public void verifyExpiresAtIsPresentAndInNearFuture() {
        final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
        assertThat(accessToken.getExpiresAtBody())
            .isBefore(ZonedDateTime.now().plusMinutes(5));
    }

    @Test
    public void verifyEncryptionAlgorithmIsCorrect() {
        final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);

        assertThat(accessToken.getHeaderClaims())
            .containsEntry(ALGORITHM.getJoseName(), BRAINPOOL256_USING_SHA256);
    }

    @Afo("A_20731")
    @Test
    public void verifyAuthTimeClaimIsPresentAndIsRecent() {
        final JsonWebToken accessToken = accessTokenBuilder.buildAccessToken(authenticationToken);
        assertThat(accessToken.getBodyClaims())
            .extractingByKey(AUTH_TIME.getJoseName())
            .extracting(authTimeValue -> TokenClaimExtraction.claimToZonedDateTime(authTimeValue),
                InstanceOfAssertFactories.ZONED_DATE_TIME)
            .isBetween(ZonedDateTime.now().minusMinutes(1), ZonedDateTime.now());
    }
}
