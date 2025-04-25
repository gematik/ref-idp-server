/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.idp.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;

import de.gematik.idp.client.data.DiscoveryDocumentResponse;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import java.util.Optional;
import kong.unirest.core.GetRequest;
import kong.unirest.core.HttpResponse;
import kong.unirest.core.UnirestInstance;
import org.apache.http.HttpHeaders;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(PkiKeyResolver.class)
@ExtendWith(MockitoExtension.class)
class AuthenticatorClientTest {

  static final String DISC_DOC_OK =
      "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwia2lkIjoicHVrX2Rpc2Nfc2lnIiwieDVjIjpbIk1JSUNzVENDQWxpZ0F3SUJBZ0lIQWJzc3FRaHFPekFLQmdncWhrak9QUVFEQWpDQmhERUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhNakF3QmdOVkJBc01LVXR2YlhCdmJtVnVkR1Z1TFVOQklHUmxjaUJVWld4bGJXRjBhV3RwYm1aeVlYTjBjblZyZEhWeU1TQXdIZ1lEVlFRRERCZEhSVTB1UzA5TlVDMURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHlNVEF4TVRVd01EQXdNREJhRncweU5qQXhNVFV5TXpVNU5UbGFNRWt4Q3pBSkJnTlZCQVlUQWtSRk1TWXdKQVlEVlFRS0RCMW5aVzFoZEdscklGUkZVMVF0VDA1TVdTQXRJRTVQVkMxV1FVeEpSREVTTUJBR0ExVUVBd3dKU1VSUUlGTnBaeUF6TUZvd0ZBWUhLb1pJemowQ0FRWUpLeVFEQXdJSUFRRUhBMElBQklZWm53aUdBbjVRWU94NDNaOE13YVpMRDNyL2J6NkJUY1FPNXBiZXVtNnFRellENWREQ2NyaXcvVk5QUFpDUXpYUVBnNFN0V3l5NU9PcTlUb2dCRW1PamdlMHdnZW93RGdZRFZSMFBBUUgvQkFRREFnZUFNQzBHQlNza0NBTURCQ1F3SWpBZ01CNHdIREFhTUF3TUNrbEVVQzFFYVdWdWMzUXdDZ1lJS29JVUFFd0VnZ1F3SVFZRFZSMGdCQm93R0RBS0JnZ3FnaFFBVEFTQlN6QUtCZ2dxZ2hRQVRBU0JJekFmQmdOVkhTTUVHREFXZ0JRbzhQam1xY2gzekVORjI1cXUxenFEckE0UHFEQTRCZ2dyQmdFRkJRY0JBUVFzTUNvd0tBWUlLd1lCQlFVSE1BR0dIR2gwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdmIyTnpjQzh3SFFZRFZSME9CQllFRkM5NE05TGdXNDRsTmdvQWJrUGFvbW5MalM4L01Bd0dBMVVkRXdFQi93UUNNQUF3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnQ2c0eVpEV215QmlyZ3h6YXd6L1M4REpuUkZLdFlVL1lHTmxSYzcra0JIY0NJQnV6YmEzR3NwcVNtb1AxVndNZU5OS05hTHNnVjh2TWJESmIzMGFxYWlYMSJdfQ.eyJhdXRob3JpemF0aW9uX2VuZHBvaW50IjoiaHR0cHM6Ly9pZHAuZGV2LmdlbWF0aWsuc29sdXRpb25zL3NpZ25fcmVzcG9uc2UiLCJhdXRoX3BhaXJfZW5kcG9pbnQiOiJodHRwczovL2lkcC5kZXYuZ2VtYXRpay5zb2x1dGlvbnMvYWx0X3Jlc3BvbnNlIiwic3NvX2VuZHBvaW50IjoiaHR0cHM6Ly9pZHAuZGV2LmdlbWF0aWsuc29sdXRpb25zL3Nzb19yZXNwb25zZSIsInVyaV9wYWlyIjoiaHR0cHM6Ly9pZHAuZGV2LmdlbWF0aWsuc29sdXRpb25zL3BhaXJpbmdzIiwidG9rZW5fZW5kcG9pbnQiOiJodHRwczovL2lkcC5kZXYuZ2VtYXRpay5zb2x1dGlvbnMvdG9rZW4iLCJmZWRlcmF0aW9uX2F1dGhvcml6YXRpb25fZW5kcG9pbnQiOiJodHRwczovL2lkcGZhZGkuZGV2LmdlbWF0aWsuc29sdXRpb25zL2F1dGgiLCJ1cmlfZGlzYyI6Imh0dHBzOi8vaWRwLmRldi5nZW1hdGlrLnNvbHV0aW9ucy8ud2VsbC1rbm93bi9vcGVuaWQtY29uZmlndXJhdGlvbiIsImlzc3VlciI6Imh0dHBzOi8vaWRwLmRldi5nZW1hdGlrLnNvbHV0aW9ucyIsImp3a3NfdXJpIjoiaHR0cHM6Ly9pZHAuZGV2LmdlbWF0aWsuc29sdXRpb25zL2p3a3MiLCJleHAiOjE3NDU0OTI1NTMsImlhdCI6MTc0NTQwNjE1MywidXJpX3B1a19pZHBfZW5jIjoiaHR0cHM6Ly9pZHAuZGV2LmdlbWF0aWsuc29sdXRpb25zL2lkcEVuYy9qd2suanNvbiIsInVyaV9wdWtfaWRwX3NpZyI6Imh0dHBzOi8vaWRwLmRldi5nZW1hdGlrLnNvbHV0aW9ucy9pZHBTaWcvandrLmpzb24iLCJzdWJqZWN0X3R5cGVzX3N1cHBvcnRlZCI6WyJwYWlyd2lzZSJdLCJpZF90b2tlbl9zaWduaW5nX2FsZ192YWx1ZXNfc3VwcG9ydGVkIjpbIkJQMjU2UjEiXSwicmVzcG9uc2VfdHlwZXNfc3VwcG9ydGVkIjpbImNvZGUiXSwic2NvcGVzX3N1cHBvcnRlZCI6WyJvcGVuaWQiLCJlLXJlemVwdCIsInBhaXJpbmciLCJnZW0tYXV0aCIsInNjb3BlLXRlbXBsYXRlIiwiZXBhIl0sInJlc3BvbnNlX21vZGVzX3N1cHBvcnRlZCI6WyJxdWVyeSJdLCJncmFudF90eXBlc19zdXBwb3J0ZWQiOlsiYXV0aG9yaXphdGlvbl9jb2RlIl0sImFjcl92YWx1ZXNfc3VwcG9ydGVkIjpbImdlbWF0aWstZWhlYWx0aC1sb2EtaGlnaCJdLCJ0b2tlbl9lbmRwb2ludF9hdXRoX21ldGhvZHNfc3VwcG9ydGVkIjpbIm5vbmUiXSwiY29kZV9jaGFsbGVuZ2VfbWV0aG9kc19zdXBwb3J0ZWQiOlsiUzI1NiJdLCJmZWRfaWRwX2xpc3RfdXJpIjoiaHR0cHM6Ly9pZHAuZGV2LmdlbWF0aWsuc29sdXRpb25zL2ZlZF9pZHBfbGlzdCJ9.l1zHWZwNaR-KcNuuhHXKKnPkL0nRcdzIv63lqcU7Mp6NG6ZjOr56KMOT4rao5yv8sVcijrseifUkZ2kFzMoeVQ"; // oder dein konkreter String

  static String DISC_DOC_NO_AUTH_PAIR_ENDPOINT =
      "eyJhbGciOiJCUDI1NlIxIiwidHlwIjoiSldUIiwia2lkIjoicHVrX2Rpc2Nfc2lnIiwieDVjIjpbIk1JSUNzVENDQWxpZ0F3SUJBZ0lIQWJzc3FRaHFPekFLQmdncWhrak9QUVFEQWpDQmhERUxNQWtHQTFVRUJoTUNSRVV4SHpBZEJnTlZCQW9NRm1kbGJXRjBhV3NnUjIxaVNDQk9UMVF0VmtGTVNVUXhNakF3QmdOVkJBc01LVXR2YlhCdmJtVnVkR1Z1TFVOQklHUmxjaUJVWld4bGJXRjBhV3RwYm1aeVlYTjBjblZyZEhWeU1TQXdIZ1lEVlFRRERCZEhSVTB1UzA5TlVDMURRVEV3SUZSRlUxUXRUMDVNV1RBZUZ3MHlNVEF4TVRVd01EQXdNREJhRncweU5qQXhNVFV5TXpVNU5UbGFNRWt4Q3pBSkJnTlZCQVlUQWtSRk1TWXdKQVlEVlFRS0RCMW5aVzFoZEdscklGUkZVMVF0VDA1TVdTQXRJRTVQVkMxV1FVeEpSREVTTUJBR0ExVUVBd3dKU1VSUUlGTnBaeUF6TUZvd0ZBWUhLb1pJemowQ0FRWUpLeVFEQXdJSUFRRUhBMElBQklZWm53aUdBbjVRWU94NDNaOE13YVpMRDNyL2J6NkJUY1FPNXBiZXVtNnFRellENWREQ2NyaXcvVk5QUFpDUXpYUVBnNFN0V3l5NU9PcTlUb2dCRW1PamdlMHdnZW93RGdZRFZSMFBBUUgvQkFRREFnZUFNQzBHQlNza0NBTURCQ1F3SWpBZ01CNHdIREFhTUF3TUNrbEVVQzFFYVdWdWMzUXdDZ1lJS29JVUFFd0VnZ1F3SVFZRFZSMGdCQm93R0RBS0JnZ3FnaFFBVEFTQlN6QUtCZ2dxZ2hRQVRBU0JJekFmQmdOVkhTTUVHREFXZ0JRbzhQam1xY2gzekVORjI1cXUxenFEckE0UHFEQTRCZ2dyQmdFRkJRY0JBUVFzTUNvd0tBWUlLd1lCQlFVSE1BR0dIR2gwZEhBNkx5OWxhR05oTG1kbGJXRjBhV3N1WkdVdmIyTnpjQzh3SFFZRFZSME9CQllFRkM5NE05TGdXNDRsTmdvQWJrUGFvbW5MalM4L01Bd0dBMVVkRXdFQi93UUNNQUF3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnQ2c0eVpEV215QmlyZ3h6YXd6L1M4REpuUkZLdFlVL1lHTmxSYzcra0JIY0NJQnV6YmEzR3NwcVNtb1AxVndNZU5OS05hTHNnVjh2TWJESmIzMGFxYWlYMSJdfQ.eyJhdXRob3JpemF0aW9uX2VuZHBvaW50IjoiZm9vYmFyc2NobWFyL3NpZ25fcmVzcG9uc2UiLCJhdXRoX3BhaXJfZW5kcG9pbnQiOm51bGwsInNzb19lbmRwb2ludCI6ImZvb2JhcnNjaG1hci9zc29fcmVzcG9uc2UiLCJ1cmlfcGFpciI6ImZvb2JhcnNjaG1hci9wYWlyaW5ncyIsInRva2VuX2VuZHBvaW50IjoiZm9vYmFyc2NobWFyL3Rva2VuIiwiZmVkZXJhdGlvbl9hdXRob3JpemF0aW9uX2VuZHBvaW50IjoiaHR0cHM6Ly9pZHBmYWRpLmRldi5nZW1hdGlrLnNvbHV0aW9ucy9hdXRoIiwidXJpX2Rpc2MiOiJmb29iYXJzY2htYXIvLndlbGwta25vd24vb3BlbmlkLWNvbmZpZ3VyYXRpb24iLCJpc3N1ZXIiOiJpc3N1ZXJVcmwiLCJqd2tzX3VyaSI6ImZvb2JhcnNjaG1hci9qd2tzIiwiZXhwIjoxNzQ1NDk3ODAxLCJpYXQiOjE3NDU0MTE0MDEsInVyaV9wdWtfaWRwX2VuYyI6ImZvb2JhcnNjaG1hci9pZHBFbmMvandrLmpzb24iLCJ1cmlfcHVrX2lkcF9zaWciOiJmb29iYXJzY2htYXIvaWRwU2lnL2p3ay5qc29uIiwic3ViamVjdF90eXBlc19zdXBwb3J0ZWQiOlsicGFpcndpc2UiXSwiaWRfdG9rZW5fc2lnbmluZ19hbGdfdmFsdWVzX3N1cHBvcnRlZCI6WyJCUDI1NlIxIl0sInJlc3BvbnNlX3R5cGVzX3N1cHBvcnRlZCI6WyJjb2RlIl0sInNjb3Blc19zdXBwb3J0ZWQiOlsib3BlbmlkIiwiZS1yZXplcHQiLCJwYWlyaW5nIiwiZ2VtLWF1dGgiLCJzY29wZS10ZW1wbGF0ZSIsImVwYSJdLCJyZXNwb25zZV9tb2Rlc19zdXBwb3J0ZWQiOlsicXVlcnkiXSwiZ3JhbnRfdHlwZXNfc3VwcG9ydGVkIjpbImF1dGhvcml6YXRpb25fY29kZSJdLCJhY3JfdmFsdWVzX3N1cHBvcnRlZCI6WyJnZW1hdGlrLWVoZWFsdGgtbG9hLWhpZ2giXSwidG9rZW5fZW5kcG9pbnRfYXV0aF9tZXRob2RzX3N1cHBvcnRlZCI6WyJub25lIl0sImNvZGVfY2hhbGxlbmdlX21ldGhvZHNfc3VwcG9ydGVkIjpbIlMyNTYiXSwiZmVkX2lkcF9saXN0X3VyaSI6ImZvb2JhcnNjaG1hci9mZWRfaWRwX2xpc3QifQ.S41DOgSgpivtXJAef9nSahkgmBWp2SWDWliZWgZDPYM0VVT3A4QRY7H1Y5ajjMxoNIfPoi5EuVtrU1ozbDrFfg";

  @Mock UnirestInstance unirestInstance;

  @Mock GetRequest getRequest;

  @Mock HttpResponse<String> httpResponse;

  AuthenticatorClient authenticatorClient;
  PkiIdentity pkiIdentity;

  @BeforeEach
  void setUp(final PkiIdentity ecc) {
    authenticatorClient = Mockito.spy(new AuthenticatorClient(unirestInstance));
    pkiIdentity = ecc;
  }

  @Test
  void retrieveDiscoveryDocument_getAuthPairEndpoint() {
    final String discoveryUrl = "https://example.com/.well-known/openid-configuration";

    when(unirestInstance.get(discoveryUrl)).thenReturn(getRequest);
    when(getRequest.header(HttpHeaders.USER_AGENT, "IdP-Client")).thenReturn(getRequest);
    when(getRequest.asString()).thenReturn(httpResponse);
    when(httpResponse.getBody()).thenReturn(DISC_DOC_OK);

    doReturn(pkiIdentity.getCertificate())
        .when(authenticatorClient)
        .retrieveServerCertFromLocation(anyString());
    doReturn(pkiIdentity.getCertificate().getPublicKey())
        .when(authenticatorClient)
        .retrieveServerPuKFromLocation(anyString());

    final DiscoveryDocumentResponse response =
        authenticatorClient.retrieveDiscoveryDocument(discoveryUrl, Optional.empty());

    // Assertions hier, z. B.:
    assertNotNull(response);
    assertThat(response.getAuthPairEndpoint())
        .isEqualTo("https://idp.dev.gematik.solutions/alt_response");
  }

  @Test
  void retrieveDiscoveryDocument_MissingAuthPairEndpoint() {
    final String discoveryUrl = "https://example.com/.well-known/openid-configuration";

    when(unirestInstance.get(discoveryUrl)).thenReturn(getRequest);
    when(getRequest.header(HttpHeaders.USER_AGENT, "IdP-Client")).thenReturn(getRequest);
    when(getRequest.asString()).thenReturn(httpResponse);
    when(httpResponse.getBody()).thenReturn(DISC_DOC_NO_AUTH_PAIR_ENDPOINT);

    doReturn(pkiIdentity.getCertificate())
        .when(authenticatorClient)
        .retrieveServerCertFromLocation(anyString());
    doReturn(pkiIdentity.getCertificate().getPublicKey())
        .when(authenticatorClient)
        .retrieveServerPuKFromLocation(anyString());

    final DiscoveryDocumentResponse response =
        authenticatorClient.retrieveDiscoveryDocument(discoveryUrl, Optional.empty());

    assertNotNull(response);
    assertThat(response.getAuthPairEndpoint())
        .isEqualTo("<IDP DOES NOT SUPPORT ALTERNATIVE AUTHENTICATION>");
  }

  // Test reproduces ANFIM-64
  @Test
  void retrieveDiscoveryDocument_MissingAuthPairEndpoint_givenFixedIdpHost() {
    final String discoveryUrl = "https://example.com/.well-known/openid-configuration";

    when(unirestInstance.get(discoveryUrl)).thenReturn(getRequest);
    when(getRequest.header(HttpHeaders.USER_AGENT, "IdP-Client")).thenReturn(getRequest);
    when(getRequest.asString()).thenReturn(httpResponse);
    when(httpResponse.getBody()).thenReturn(DISC_DOC_NO_AUTH_PAIR_ENDPOINT);

    doReturn(pkiIdentity.getCertificate())
        .when(authenticatorClient)
        .retrieveServerCertFromLocation(anyString());
    doReturn(pkiIdentity.getCertificate().getPublicKey())
        .when(authenticatorClient)
        .retrieveServerPuKFromLocation(anyString());

    final DiscoveryDocumentResponse response =
        authenticatorClient.retrieveDiscoveryDocument(
            discoveryUrl, Optional.of("https://example.com"));

    assertNotNull(response);
    assertThat(response.getAuthPairEndpoint())
        .isEqualTo("<IDP DOES NOT SUPPORT ALTERNATIVE AUTHENTICATION>");
  }
}
