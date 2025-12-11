/*
 * Copyright (Change Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import de.gematik.idp.data.UserConsent;
import java.util.Map;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.UnirestInstance;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.model.MediaType;
import tools.jackson.databind.json.JsonMapper;

class HttpResponseAuthenticationChallengeTest {

  private ClientAndServer mockServer;
  private UnirestInstance unirestInstance;
  private JsonMapper objectMapper;
  private static final int MOCK_SERVER_PORT = 8888;

  @BeforeEach
  void setUp() {
    mockServer = ClientAndServer.startClientAndServer(MOCK_SERVER_PORT);
    unirestInstance = Unirest.spawnInstance();

    objectMapper = JsonMapper.builder().findAndAddModules().build();

    unirestInstance
        .config()
        .setObjectMapper(
            new kong.unirest.core.ObjectMapper() {
              @Override
              public <T> T readValue(final String value, final Class<T> valueType) {
                try {
                  return objectMapper.readValue(value, valueType);
                } catch (final Exception e) {
                  throw new RuntimeException(e);
                }
              }

              @Override
              public String writeValue(final Object value) {
                try {
                  return objectMapper.writeValueAsString(value);
                } catch (final Exception e) {
                  throw new RuntimeException(e);
                }
              }
            });
  }

  @AfterEach
  void tearDown() {
    mockServer.stop();
    unirestInstance.close();
  }

  @Test
  void shouldDeserializeAuthenticationChallengeFromHttpResponse() throws Exception {
    final String responseJson = createAuthChallengeJson();

    mockServer
        .when(request().withMethod("GET").withPath("/auth"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(responseJson));

    final HttpResponse<AuthenticationChallenge> httpResponse =
        unirestInstance
            .get("http://localhost:" + MOCK_SERVER_PORT + "/auth")
            .header("Accept", "application/json")
            .asObject(AuthenticationChallenge.class);

    assertThat(httpResponse.getStatus()).isEqualTo(200);
    assertThat(httpResponse.isSuccess()).isTrue();

    final AuthenticationChallenge challenge = httpResponse.getBody();
    assertThat(challenge).isNotNull();
    assertThat(challenge.getUserConsent()).isNotNull();
    assertThat(challenge.getUserConsent().getRequestedScopes())
        .containsEntry("openid", "read")
        .containsEntry("profile", "read");
    assertThat(challenge.getUserConsent().getRequestedClaims())
        .containsEntry("sub", "required")
        .containsEntry("name", "optional");
  }

  @Test
  void shouldHandleNullFieldsInHttpResponse() {
    final String responseJson = "{\"challenge\":null,\"user_consent\":null}";

    mockServer
        .when(request().withMethod("GET").withPath("/auth"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(responseJson));

    final HttpResponse<AuthenticationChallenge> httpResponse =
        unirestInstance
            .get("http://localhost:" + MOCK_SERVER_PORT + "/auth")
            .asObject(AuthenticationChallenge.class);

    assertThat(httpResponse.isSuccess()).isTrue();
    final AuthenticationChallenge challenge = httpResponse.getBody();
    assertThat(challenge).isNotNull();
    assertThat(challenge.getChallenge()).isNull();
    assertThat(challenge.getUserConsent()).isNull();
  }

  @Test
  void shouldHandleUserConsentWithSnakeCaseFields() {
    final String responseJson =
        """
            {
              "user_consent": {
                "requested_scopes": {
                  "email": "read",
                  "profile": "write"
                },
                "requested_claims": {
                  "email": "required",
                  "picture": "optional"
                }
              }
            }
            """;

    mockServer
        .when(request().withMethod("GET").withPath("/auth"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(responseJson));

    final HttpResponse<AuthenticationChallenge> httpResponse =
        unirestInstance
            .get("http://localhost:" + MOCK_SERVER_PORT + "/auth")
            .asObject(AuthenticationChallenge.class);

    assertThat(httpResponse.isSuccess()).isTrue();

    final UserConsent consent = httpResponse.getBody().getUserConsent();
    assertThat(consent).isNotNull();
    assertThat(consent.getRequestedScopes())
        .hasSize(2)
        .containsEntry("email", "read")
        .containsEntry("profile", "write");
    assertThat(consent.getRequestedClaims())
        .hasSize(2)
        .containsEntry("email", "required")
        .containsEntry("picture", "optional");
  }

  @Test
  void shouldHandleEmptyUserConsentMaps() {
    final String responseJson =
        """
            {
              "user_consent": {
                "requested_scopes": {},
                "requested_claims": {}
              }
            }
            """;

    mockServer
        .when(request().withMethod("GET").withPath("/auth"))
        .respond(
            response()
                .withStatusCode(200)
                .withContentType(MediaType.APPLICATION_JSON)
                .withBody(responseJson));

    final HttpResponse<AuthenticationChallenge> httpResponse =
        unirestInstance
            .get("http://localhost:" + MOCK_SERVER_PORT + "/auth")
            .asObject(AuthenticationChallenge.class);

    assertThat(httpResponse.isSuccess()).isTrue();
    final UserConsent consent = httpResponse.getBody().getUserConsent();
    assertThat(consent.getRequestedScopes()).isEmpty();
    assertThat(consent.getRequestedClaims()).isEmpty();
  }

  private String createAuthChallengeJson() {
    final Map<String, String> scopes =
        Map.of(
            "openid", "read",
            "profile", "read");
    final Map<String, String> claims =
        Map.of(
            "sub", "required",
            "name", "optional");

    final UserConsent consent =
        UserConsent.builder().requestedScopes(scopes).requestedClaims(claims).build();

    final AuthenticationChallenge challenge =
        AuthenticationChallenge.builder().userConsent(consent).build();

    return objectMapper.writeValueAsString(challenge);
  }
}
