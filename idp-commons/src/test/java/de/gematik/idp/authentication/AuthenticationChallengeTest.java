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

import de.gematik.idp.data.UserConsent;
import de.gematik.idp.token.JsonWebToken;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class AuthenticationChallengeTest {

  private JsonMapper jsonMapper;
  static final String SIGNED_CHALLENGE =
      "eyJ0eXAiOiJKV1QiLCJjdHkiOiJOSldUIiwieDVjIjpbIk1JSUMrakNDQXFDZ0F3SUJBZ0lIQXdBVGFsZGZWVEFLQmdncWhrak9QUVFEQWpDQmxqRUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhSVEJEQmdOVkJBc01QRVZzWld0MGNtOXVhWE5qYUdVZ1IyVnpkVzVrYUdWcGRITnJZWEowWlMxRFFTQmtaWElnVkdWc1pXMWhkR2xyYVc1bWNtRnpkSEoxYTNSMWNqRWZNQjBHQTFVRUF3d1dSMFZOTGtWSFN5MURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHhPVEEwTURneU1qQXdNREJhRncweU5EQTBNRGd5TVRVNU5UbGFNSDB4Q3pBSkJnTlZCQVlUQWtSRk1SRXdEd1lEVlFRS0RBaEJUMHNnVUd4MWN6RVNNQkFHQTFVRUN3d0pNVEE1TlRBd09UWTVNUk13RVFZRFZRUUxEQXBZTVRFME5ESTROVE13TVE0d0RBWURWUVFFREFWR2RXTm9jekVOTUFzR0ExVUVLZ3dFU25WdVlURVRNQkVHQTFVRUF3d0tTblZ1WVNCR2RXTm9jekJhTUJRR0J5cUdTTTQ5QWdFR0NTc2tBd01DQ0FFQkJ3TkNBQVIxTmRyckk4b0tNaXYweHRVWEY1b3NTN3piRklLeEd0L0J3aXN1a1dvRUs1R3NKMWNDeUdFcENIMHNzOEp2RDRPQUhKUzhJTW0xL3JNNTlqbGlTKzFPbzRIdk1JSHNNQjBHQTFVZERnUVdCQlNjRVo1SDFVeFNNaFBzT2NXWmhHOFpRZVdodlRBTUJnTlZIUk1CQWY4RUFqQUFNREFHQlNza0NBTURCQ2N3SlRBak1DRXdIekFkTUJBTURsWmxjbk5wWTJobGNuUmxMeTF5TUFrR0J5cUNGQUJNQkRFd0h3WURWUjBqQkJnd0ZvQVVSTEZNQVZoVUh0elpONzdrc2o4cWJxUmNpUjB3SUFZRFZSMGdCQmt3RnpBS0JnZ3FnaFFBVEFTQkl6QUpCZ2NxZ2hRQVRBUkdNQTRHQTFVZER3RUIvd1FFQXdJSGdEQTRCZ2dyQmdFRkJRY0JBUVFzTUNvd0tBWUlLd1lCQlFVSE1BR0dIR2gwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdmIyTnpjQzh3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUlQSWNiR2pKUXh1VUdiSm1CVWltV3ZiVWk3bStTdVhZQmNSR0Z5WjBqSUpBaUFtMUlXSWZ2L2dOYy9XbXc0Wk8rNzMwUTlDNWRjY0ZuTWptdmJKZTdpNzVnPT0iXSwiYWxnIjoiQlAyNTZSMSJ9.eyJuand0IjoiZXlKaGJHY2lPaUpDVURJMU5sSXhJaXdpZEhsd0lqb2lTbGRVSWl3aWEybGtJam9pYzJWeWRtVnlTMlY1U1dSbGJuUnBkSGtpZlEuZXlKcGMzTWlPbTUxYkd3c0luSmxjM0J2Ym5ObFgzUjVjR1VpT2lKamIyUmxJaXdpYzI1aklqb2lhVFJDTVhCUExYUXRiSFZCYjJsSlRqRjFlbmN4V2xWdFdEZEJNbUZpZFVoUVYzWXdSa2hrVDFCclp5SXNJbU52WkdWZlkyaGhiR3hsYm1kbFgyMWxkR2h2WkNJNklsTXlOVFlpTENKMGIydGxibDkwZVhCbElqb2lZMmhoYkd4bGJtZGxJaXdpYm05dVkyVWlPaUp1YjI1alpWWmhiSFZsSWl3aVkyeHBaVzUwWDJsa0lqb2laMjl2SWl3aWMyTnZjR1VpT2lKdmNHVnVhV1FnWlMxeVpYcGxjSFFpTENKemRHRjBaU0k2SW1admJ5SXNJbkpsWkdseVpXTjBYM1Z5YVNJNkltSmhjaUlzSW1WNGNDSTZNVFkyTVRnME9ERXpPU3dpYVdGMElqb3hOall4T0RRM09UVTVMQ0pqYjJSbFgyTm9ZV3hzWlc1blpTSTZJbk5qYUcxaGNpSXNJbXAwYVNJNklqRTNNR0poTkRrek5qUXdaVEJrTldVaWZRLk9VMnF3UEVxdnpubXRHTkNCSGRBSTZPQ2R6cE5XLVNpOHhOTFpnbi0ya2NpNnNQd05UckRvdm1xZmptWnVxQ3NuVkI5TW42eWctZmFIV0Eya1ZuN1J3In0.ndsBrCrNq4C2rLi89dGT6blAYCzbpY5ZojTMvKvGtxBln7tEiCf-_8Za1Vjl6OUtEGrk_RtCWyojg3BqjIWHCw";
  static final JsonWebToken JSON_WEB_TOKEN = new JsonWebToken(SIGNED_CHALLENGE);

  @BeforeEach
  void setUp() {
    jsonMapper = JsonMapper.builder().build();
  }

  @Test
  void shouldSerializeAndDeserializeWithAllFields() {
    final UserConsent consent = createTestConsent();

    final AuthenticationChallenge original =
        AuthenticationChallenge.builder().challenge(JSON_WEB_TOKEN).userConsent(consent).build();

    final String json = jsonMapper.writeValueAsString(original);
    final AuthenticationChallenge deserialized =
        jsonMapper.readValue(json, AuthenticationChallenge.class);

    assertThat(deserialized).isNotNull();
    assertThat(deserialized.getChallenge()).isEqualTo(original.getChallenge());
    assertThat(deserialized.getUserConsent()).isEqualTo(original.getUserConsent());
  }

  @Test
  void shouldSerializeUserConsentFieldWithCustomName() {
    final UserConsent consent = createTestConsent();
    final AuthenticationChallenge challenge =
        AuthenticationChallenge.builder().userConsent(consent).build();

    final String json = jsonMapper.writeValueAsString(challenge);

    assertThat(json).contains("\"user_consent\"");
    assertThat(json).doesNotContain("\"userConsent\"");

    assertThat(json).contains("\"requested_scopes\"");
    assertThat(json).contains("\"requested_claims\"");
  }

  @Test
  void shouldDeserializeUserConsentFromCustomFieldName() {
    final String json =
        """
                {
                  "user_consent": {
                    "requested_scopes": {"profile": "read"},
                    "requested_claims": {"email": "optional"}
                  }
                }
                """;

    final AuthenticationChallenge challenge =
        jsonMapper.readValue(json, AuthenticationChallenge.class);

    assertThat(challenge.getUserConsent()).isNotNull();
    assertThat(challenge.getUserConsent().getRequestedScopes()).containsEntry("profile", "read");
    assertThat(challenge.getUserConsent().getRequestedClaims()).containsEntry("email", "optional");
  }

  @Test
  void shouldHandleNullFields() {
    final AuthenticationChallenge original = new AuthenticationChallenge();

    final String json = jsonMapper.writeValueAsString(original);
    final AuthenticationChallenge deserialized =
        jsonMapper.readValue(json, AuthenticationChallenge.class);

    assertThat(deserialized).isNotNull();
    assertThat(deserialized.getChallenge()).isNull();
    assertThat(deserialized.getUserConsent()).isNull();
  }

  @Test
  void shouldUseNoArgsConstructorForDeserialization() {
    final String json = "{\"challenge\":null,\"user_consent\":null}";

    final AuthenticationChallenge challenge =
        jsonMapper.readValue(json, AuthenticationChallenge.class);

    assertThat(challenge).isNotNull();
  }

  @Test
  void shouldUseBuilderCorrectly() {
    final AuthenticationChallenge challenge =
        AuthenticationChallenge.builder()
            .challenge(JSON_WEB_TOKEN)
            .userConsent(createTestConsent())
            .build();

    assertThat(challenge.getChallenge()).isNotNull();
    assertThat(challenge.getUserConsent()).isNotNull();
  }

  @Test
  void shouldDeserializeUserConsentWithEmptyMaps() {
    final String json =
        """
                {
                  "user_consent": {
                    "requested_scopes": {},
                    "requested_claims": {}
                  }
                }
                """;

    final AuthenticationChallenge challenge =
        jsonMapper.readValue(json, AuthenticationChallenge.class);

    assertThat(challenge.getUserConsent()).isNotNull();
    assertThat(challenge.getUserConsent().getRequestedScopes()).isEmpty();
    assertThat(challenge.getUserConsent().getRequestedClaims()).isEmpty();
  }

  private UserConsent createTestConsent() {
    final Map<String, String> scopes =
        Map.of(
            "scope01", "read",
            "scope02", "read");
    final Map<String, String> claims =
        Map.of(
            "claim01", "required",
            "claim02", "optional");

    return UserConsent.builder().requestedScopes(scopes).requestedClaims(claims).build();
  }
}
