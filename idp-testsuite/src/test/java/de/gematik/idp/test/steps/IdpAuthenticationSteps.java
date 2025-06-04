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

package de.gematik.idp.test.steps;

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

  private void updateContext(
      final IdpEndpointType idpEndpointType,
      final Map<String, Object> ctxt,
      final Map<String, String> mapParsedParams) {
    if (idpEndpointType == IdpEndpointType.Smartcard_IDP) {
      if (mapParsedParams.containsKey("client_id")) {
        final String cid = mapParsedParams.get("client_id");
        ctxt.put(ContextKey.CLIENT_ID, cid);
      }
    }
  }
}
