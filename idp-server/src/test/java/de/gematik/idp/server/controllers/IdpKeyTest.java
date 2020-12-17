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

package de.gematik.idp.server.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.lang.JoseException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(PkiKeyResolver.class)
public class IdpKeyTest {
    private ObjectMapper mapper = new ObjectMapper();

    @Test
    public void rsaKey_ShouldBeConvertedCorrectly(@PkiKeyResolver.Filename("rsa") PkiIdentity rsaIdentity) throws JsonProcessingException, JoseException {
        IdpKey key = new IdpKey(rsaIdentity);

        final JsonWebKeySet keySet = new JsonWebKeySet(mapper.writeValueAsString(key.buildJwks()));

        assertThat(keySet.getJsonWebKeys())
                .isNotEmpty();
    }

    @Test
    public void eccKey_ShouldBeConvertedCorrectly(@PkiKeyResolver.Filename("ecc") PkiIdentity eccIdentity) throws JsonProcessingException, JoseException {
        IdpKey key = new IdpKey(eccIdentity);

        final JsonWebKeySet keySet = new JsonWebKeySet(mapper.writeValueAsString(key.buildJwks()));

        assertThat(keySet.getJsonWebKeys())
                .isNotEmpty();
    }
}
