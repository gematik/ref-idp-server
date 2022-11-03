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

package de.gematik.idp.test.steps;

import static de.gematik.idp.IdpConstants.FED_AUTH_APP_ENDPOINT;
import static de.gematik.idp.IdpConstants.FED_AUTH_ENDPOINT;

import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.idp.test.steps.model.IdpEndpointType;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.SneakyThrows;
import org.apache.commons.codec.digest.DigestUtils;
import org.jetbrains.annotations.NotNull;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.web.util.UriComponentsBuilder;

public class IdpAuthenticationSteps extends IdpStepsBase {

  public void setCodeVerifier(final String codeverifier) {
    Context.get().put(ContextKey.CODE_VERIFIER, codeverifier);
  }

  @SneakyThrows
  public String generateCodeChallenge(final String codeVerifier) {
    final byte[] bytes = codeVerifier.getBytes(StandardCharsets.UTF_8);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(DigestUtils.sha256(bytes));
  }

  public void getChallenge(final Map<String, String> mapParsedParams, final HttpStatus status)
      throws JSONException {
    final Map<String, Object> ctxt = de.gematik.test.bdd.Context.get().getMapForCurrentThread();
    if (mapParsedParams.containsKey("client_id")) {
      final String cid = mapParsedParams.get("client_id");
      ctxt.put(ContextKey.CLIENT_ID, cid);
    }
    ctxt.put(
        ContextKey.RESPONSE,
        requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getAuthorizationEndpoint(),
            null,
            HttpMethods.GET,
            mapParsedParams,
            null,
            status));

    final HttpStatus responseStatus = new HttpStatus(Context.getCurrentResponse().getStatusCode());
    if (responseStatus.isError() || responseStatus.is3xxRedirection()) {
      ctxt.put(ContextKey.CHALLENGE, null);
      ctxt.put(ContextKey.USER_CONSENT, null);
    } else {
      final JSONObject json = new JSONObject(Context.getCurrentResponse().getBody().asString());
      ctxt.put(ContextKey.CHALLENGE, json.getString("challenge"));
      ctxt.put(ContextKey.USER_CONSENT, json.getJSONObject("user_consent"));
    }
  }

  public void sendAuthorizationRequest(
      final IdpEndpointType idpEndpointType,
      Map<String, String> mapParsedParams,
      final HttpStatus status) {

    final Map<String, Object> ctxt = de.gematik.test.bdd.Context.get().getMapForCurrentThread();
    mapParsedParams = applyIfRedirect(mapParsedParams);
    updateContext(idpEndpointType, ctxt, mapParsedParams);
    updateMap(idpEndpointType, mapParsedParams);
    final String url = getAuthUrl(idpEndpointType);

    ctxt.put(
        ContextKey.RESPONSE,
        requestResponseAndAssertStatus(url, null, HttpMethods.GET, mapParsedParams, null, status));
  }

  public void sendAuthorizationCode(Map<String, String> mapParsedParams, final HttpStatus status) {
    mapParsedParams = applyIfRedirect(mapParsedParams);
    final Map<String, Object> ctxt = de.gematik.test.bdd.Context.get().getMapForCurrentThread();
    final String url = getAuthUrl(IdpEndpointType.Fachdienst);
    ctxt.put(
        ContextKey.RESPONSE,
        requestResponseAndAssertStatus(url, null, HttpMethods.POST, mapParsedParams, null, status));
  }

  @NotNull
  public Map<String, String> getFillFromRedirect(
      final Map<String, String> mapParsedParams, final Map<String, String> parameters) {
    return mapParsedParams.entrySet().stream()
        .collect(
            Collectors.toMap(
                Map.Entry::getKey,
                e ->
                    e.getValue().equals("$FILL_FROM_REDIRECT")
                        ? parameters.get(e.getKey())
                        : e.getValue()));
  }

  public Map<String, String> applyIfRedirect(final Map<String, String> mapParsedParams) {
    if (mapParsedParams.containsValue("$FILL_FROM_REDIRECT")) {
      final String location = getLocationHeader(Context.getCurrentResponse());
      final Map<String, String> parameters =
          UriComponentsBuilder.fromUriString(location).build().getQueryParams().toSingleValueMap();
      return getFillFromRedirect(mapParsedParams, parameters);
    }
    return mapParsedParams;
  }

  private String getAuthUrl(final IdpEndpointType idpEndpointType) {
    final String url;
    switch (idpEndpointType) {
      case Fasttrack_Sektoral_IDP:
        url = Context.get().getString(ContextKey.AUTH_URL_SEKTORAL_IDP);
        break;
      case Fed_Sektoral_IDP:
        url = Context.get().getString(ContextKey.ISS_IDP_SEKTORAL) + FED_AUTH_ENDPOINT;
        break;
      case Fed_Sektoral_IDP_APP:
        url = Context.get().getString(ContextKey.ISS_IDP_SEKTORAL) + FED_AUTH_APP_ENDPOINT;
        break;
      case Fachdienst:
        url = Context.get().getString(ContextKey.FACHDIENST_URL) + FED_AUTH_ENDPOINT;
        break;
      case Smartcard_IDP:
        url = Context.getDiscoveryDocument().getThirdPartyEndpoint();
        break;
      default:
        throw new java.lang.IllegalStateException("Unexpected value: " + idpEndpointType);
    }
    return url;
  }

  private void updateMap(
      final IdpEndpointType idpEndpointType, Map<String, String> mapParsedParams) {
    if (idpEndpointType == IdpEndpointType.Fachdienst) {
      if (!mapParsedParams.containsKey("idp_iss")) {
        mapParsedParams.put("idp_iss", Context.get().getString(ContextKey.ISS_IDP_SEKTORAL));
      }
    }
  }

  private void updateContext(
      final IdpEndpointType idpEndpointType,
      Map<String, Object> ctxt,
      Map<String, String> mapParsedParams) {
    if (idpEndpointType == IdpEndpointType.Smartcard_IDP) {
      if (mapParsedParams.containsKey("client_id")) {
        final String cid = mapParsedParams.get("client_id");
        ctxt.put(ContextKey.CLIENT_ID, cid);
      }
    }
  }
}
