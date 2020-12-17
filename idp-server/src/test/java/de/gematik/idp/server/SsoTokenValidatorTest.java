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

package de.gematik.idp.server;

import static de.gematik.idp.field.ClaimName.*;
import static org.assertj.core.api.AssertionsForClassTypes.*;
import static org.junit.jupiter.api.Assertions.*;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtDescription;
import de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.SsoTokenValidator;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.SsoTokenBuilder;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class SsoTokenValidatorTest {

    private SsoTokenValidator ssoTokenValidator;
    private PkiIdentity rsaUserIdentity;
    private PkiIdentity egkUserIdentity;
    private IdpJwtProcessor serverTokenProzessor;
    private SsoTokenBuilder ssoTokenBuilder;

    @BeforeEach
    public void init(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity,
        @PkiKeyResolver.Filename("rsa") final PkiIdentity rsaIdentity) {
        egkUserIdentity = egkIdentity;
        rsaUserIdentity = rsaIdentity;
        final IdpKey serverKey = new IdpKey(egkUserIdentity);
        serverTokenProzessor = new IdpJwtProcessor(egkUserIdentity);
        ssoTokenBuilder = new SsoTokenBuilder(serverTokenProzessor);
        ssoTokenValidator = new SsoTokenValidator(serverKey);
    }

    @Test
    public void validateValidSsoToken() {
        assertDoesNotThrow(() -> ssoTokenValidator.validateSsoToken(generateValidSsoToken()));
    }

    @Test
    public void validateSsoTokenExpired() {
        assertThatThrownBy(() -> ssoTokenValidator.validateSsoToken(generateExpiredSsoToken()))
            .isInstanceOf(IdpServerException.class);
    }

    @Test
    public void validateSsoTokenInvalidCert() {
        assertThatThrownBy(() -> ssoTokenValidator.validateSsoToken(generateInvalidSsoToken()))
            .isInstanceOf(IdpJoseException.class);
    }

    private JsonWebToken generateExpiredSsoToken() {
        return serverTokenProzessor.buildJwt(JwtDescription.builder()
            .headers(generateHeaderClaims())
            .claims(generateBodyClaims())
            .expiresAt(ZonedDateTime.now().minusMinutes(1))
            .build());
    }

    private JsonWebToken generateInvalidSsoToken() {
        final IdpJwtProcessor invalidProcessor = new IdpJwtProcessor(rsaUserIdentity);
        return invalidProcessor.buildJwt(JwtDescription.builder()
            .headers(generateHeaderClaims())
            .claims(generateBodyClaims())
            .expiresAt(ZonedDateTime.now().plusMinutes(5))
            .build());
    }

    private Map<String, Object> generateHeaderClaims() {
        final Map<String, Object> headerClaims = new HashMap<>();
        headerClaims.put(ALGORITHM.getJoseName(), BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256);
        headerClaims.put(TYPE.getJoseName(), "application/jwt");
        headerClaims.put(JWT_ID.getJoseName(), new Nonce().getNonceAsHex(16));
        return headerClaims;
    }

    private Map<String, Object> generateBodyClaims() {
        final Map<String, Object> bodyClaims = new HashMap<>();
        bodyClaims.put(ISSUED_AT.getJoseName(), ZonedDateTime.now().toEpochSecond());
        bodyClaims.put(NOT_BEFORE.getJoseName(), ZonedDateTime.now().toEpochSecond());
        return bodyClaims;
    }

    private JsonWebToken generateValidSsoToken() {
        final Map<String, Object> bodyClaims = new HashMap<>();
        return ssoTokenBuilder.buildSsoToken(egkUserIdentity.getCertificate(), ZonedDateTime.now());
    }

}
