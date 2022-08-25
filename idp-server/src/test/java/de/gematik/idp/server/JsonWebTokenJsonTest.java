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

package de.gematik.idp.server;


import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.client.data.AuthorizationResponse;
import de.gematik.idp.token.JsonWebToken;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.json.JacksonTester;
import org.springframework.boot.test.json.JsonContent;

class JsonWebTokenJsonTest {

    private JacksonTester<AuthorizationResponse> jacksonTester;

    @BeforeEach
    public void setup() {
        final ObjectMapper objectMapper = new ObjectMapper();
        JacksonTester.initFields(this, objectMapper);
    }

    @Test
    void testSerialization() throws IOException {
        final JsonContent<AuthorizationResponse> jsonContent = jacksonTester.write(AuthorizationResponse.builder()
            .authenticationChallenge(AuthenticationChallenge.builder()
                .challenge(new JsonWebToken("foobar"))
                .build())
            .build());

        assertThat(jsonContent.getJson())
            .contains("\"challenge\":\"foobar\"");
    }
}
