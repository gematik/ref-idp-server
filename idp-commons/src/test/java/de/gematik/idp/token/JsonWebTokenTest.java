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

import static de.gematik.idp.field.ClaimName.CONFIRMATION;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.RandomStringUtils;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class JsonWebTokenTest {

    private IdpJwtProcessor idpJwtProcessor;
    private SecretKeySpec aesKey;
    private PkiIdentity identity;

    @BeforeEach
    public void setup(@PkiKeyResolver.Filename("ecc") final PkiIdentity identity) {
        idpJwtProcessor = new IdpJwtProcessor(identity);
        aesKey = new SecretKeySpec(RandomStringUtils.randomAlphanumeric(256 / 8).getBytes(), "AES");
        this.identity = identity;
    }

    @Test
    public void getTokenExp_ShouldBeCorrect() {
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(new JwtBuilder()
            .expiresAt(ZonedDateTime.now().plusMinutes(5)));

        Assertions.assertThat(jsonWebToken.getExpiresAt())
            .isBetween(ZonedDateTime.now().plusMinutes(4),
                ZonedDateTime.now().plusMinutes(6));
    }

    @Test
    public void getBodyClaims_shouldMatch() {
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(new JwtBuilder()
            .addAllBodyClaims(Map.of("foo", "bar"))
            .expiresAt(ZonedDateTime.now().plusMinutes(5)));

        Assertions.assertThat(jsonWebToken.getBodyClaims())
            .containsEntry("foo", "bar");
    }

    @Test
    public void getHeaderClaims_shouldMatch() {
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(new JwtBuilder()
            .addAllHeaderClaims(new HashMap<>(Map.of("foo", "bar")))
            .expiresAt(ZonedDateTime.now().plusMinutes(5)));

        Assertions.assertThat(jsonWebToken.getHeaderClaims())
            .containsEntry("foo", "bar")
            .containsEntry("alg", "BP256R1");
    }

    @Test
    public void getStringBodyClaims_shouldMatch() {
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(new JwtBuilder()
            .addAllBodyClaims(Map.of("foo", "bar")));

        assertThat(jsonWebToken.getBodyClaims().get("foo"))
            .isEqualTo("bar");
    }

    @Test
    public void getDateTimeBodyClaims_shouldMatch() {
        final ZonedDateTime now = ZonedDateTime.now();
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(new JwtBuilder()
            .addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), now.toEpochSecond())));

        Assertions.assertThat(jsonWebToken.getDateTimeClaim(CONFIRMATION, jsonWebToken::getBodyClaims))
            .get(InstanceOfAssertFactories.ZONED_DATE_TIME)
            .isEqualToIgnoringNanos(now);
    }

    @Test
    public void encryptJwtWithEcc_shouldBeJweStructure(
        @Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity id) {
        final JsonWebToken jsonWebToken = idpJwtProcessor
            .buildJwt(new JwtBuilder().addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), "foobarschmar")));

        assertThat(jsonWebToken.encrypt(id.getCertificate().getPublicKey())
            .decrypt(id.getPrivateKey())
            .getBodyClaim(CONFIRMATION))
            .get()
            .isEqualTo("foobarschmar");
    }

    @Test
    public void encryptJwtWithAes_shouldBeJweStructure() {
        final JsonWebToken jsonWebToken = idpJwtProcessor
            .buildJwt(new JwtBuilder().addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), ZonedDateTime.now())));

        assertThat(jsonWebToken.encrypt(aesKey).getRawValue())
            .matches("(?:.*\\.){4}.*"); // 5 Teile Base64
    }

    @Test
    public void decryptJweWithAes_shouldMatchSourceJwt() {
        final JsonWebToken jsonWebToken = idpJwtProcessor
            .buildJwt(new JwtBuilder().addAllBodyClaims(Map.of(CONFIRMATION.getJoseName(), "foobarschmar")));

        assertThat(jsonWebToken
            .encrypt(aesKey)
            .decrypt(aesKey).getBodyClaim(CONFIRMATION))
            .get()
            .isEqualTo("foobarschmar");
    }

    public void extractClientCertificate_shouldMatch() {
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(new JwtBuilder()
            .includeSignerCertificateInHeader(true)
            .expiresAt(ZonedDateTime.now()));
        Assertions.assertThat(jsonWebToken.getClientCertificateFromHeader())
            .get()
            .isEqualTo(identity.getCertificate());
    }
}
