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

package de.gematik.idp.token;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.Afo;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.Rfc;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import java.time.ZonedDateTime;

import static de.gematik.idp.field.ClaimName.*;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(PkiKeyResolver.class)
public class IdTokenBuilderTest {

    private IdTokenBuilder idTokenBuilder;
    private JsonWebToken idToken;
    private static final long maxIdTokenExpirationInSec = 86400;

    @BeforeEach
    public void init(@PkiKeyResolver.Filename("authz_rsa") final PkiIdentity clientIdentity) {
        idTokenBuilder = new IdTokenBuilder(new IdpJwtProcessor(clientIdentity));
        idToken = idTokenBuilder.buildIdToken(IdpConstants.CLIENT_ID);
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 2 ID Token")
    @Afo("A_20313")
    @Afo("TODO A_20297/ML-110385?")
    @Test
    public void checkIdTokenClaims() {
        assertThat(idToken.getBodyClaims())
                .containsKey(ISSUER.getJoseName())
                .containsEntry(SUBJECT.getJoseName(), IdpConstants.CLIENT_ID)
                .containsKey(AUDIENCE.getJoseName())
                .containsKey(EXPIRES_AT.getJoseName())
                .containsKey(ISSUED_AT.getJoseName())
                .containsKey(NOT_BEFORE.getJoseName());
        assertThat(idToken.getHeaderClaims())
                .containsKey(ALGORITHM.getJoseName());
    }

    @Rfc("OpenID Connect Core 1.0 incorporating errata set 1 - 2 ID Token")
    @Afo("A_20462")
    @Test
    public void checkIdTokenClaimTimestamps() {
        final long now = ZonedDateTime.now().toEpochSecond();
        final long exp = (long) idToken.getBodyClaims().get(EXPIRES_AT.getJoseName());
        final long iat = (long) idToken.getBodyClaims().get(ISSUED_AT.getJoseName());
        final long nbf = (long) idToken.getBodyClaims().get(NOT_BEFORE.getJoseName());

        assertThat(now).isGreaterThanOrEqualTo(iat);
        assertThat(now).isGreaterThanOrEqualTo(nbf);
        assertThat(now).isLessThan(exp);
        assertThat(exp - now).isLessThan(maxIdTokenExpirationInSec);
    }
}
