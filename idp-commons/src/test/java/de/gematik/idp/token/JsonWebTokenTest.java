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
import de.gematik.idp.authentication.JwtDescription;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class JsonWebTokenTest {

    private IdpJwtProcessor idpJwtProcessor;

    @BeforeEach
    public void setup(final PkiIdentity ecc) {
        idpJwtProcessor = new IdpJwtProcessor(ecc);
    }

    @Test
    public void getTokenExp_ShouldBeCorrect() {
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(JwtDescription.builder()
            .expiresAt(ZonedDateTime.now().plusMinutes(5))
            .build());

        Assertions.assertThat(jsonWebToken.getExpiresAt())
            .isBetween(ZonedDateTime.now().plusMinutes(4),
                ZonedDateTime.now().plusMinutes(6));
    }

    @Test
    public void getBodyClaims_shouldMatch() {
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(JwtDescription.builder()
            .claims(Map.of("foo", "bar"))
            .expiresAt(ZonedDateTime.now().plusMinutes(5))
            .build());

        Assertions.assertThat(jsonWebToken.getBodyClaims())
            .containsEntry("foo", "bar");
    }

    @Test
    public void getHeaderClaims_shouldMatch() {
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(JwtDescription.builder()
            .headers(new HashMap<>(Map.of("foo", "bar")))
            .expiresAt(ZonedDateTime.now().plusMinutes(5))
            .build());

        Assertions.assertThat(jsonWebToken.getHeaderClaims())
            .containsEntry("foo", "bar")
            .containsEntry("alg", "BP256R1");
    }

    @Test
    public void getStringBodyClaims_shouldMatch() {
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(JwtDescription.builder()
            .claims(Map.of("foo", "bar"))
            .build());

        assertThat(jsonWebToken.getBodyClaims().get("foo"))
            .isEqualTo("bar");
    }

    @Test
    public void getDateTimeBodyClaims_shouldMatch() {
        final ZonedDateTime now = ZonedDateTime.now();
        final JsonWebToken jsonWebToken = idpJwtProcessor.buildJwt(JwtDescription.builder()
            .claims(Map.of(CONFIRMATION.getJoseName(), now.toEpochSecond()))
            .build());

        Assertions.assertThat(jsonWebToken.getDateTimeClaim(CONFIRMATION, () -> jsonWebToken.getBodyClaims()))
            .get(InstanceOfAssertFactories.ZONED_DATE_TIME)
            .isEqualToIgnoringNanos(now);
    }
}
