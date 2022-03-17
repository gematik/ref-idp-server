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

package de.gematik.idp.fachdienst.controller;

import static de.gematik.idp.IdpConstants.FACHDIENST_AUTHORIZATION_ENDPOINT;
import static de.gematik.idp.field.ClientUtilities.generateCodeChallenge;
import static de.gematik.idp.field.ClientUtilities.generateCodeVerifier;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.fedidp.ParResponse;
import de.gematik.idp.fachdienst.ServerUrlService;
import de.gematik.idp.fachdienst.data.FachdienstAuthSession;
import de.gematik.idp.fachdienst.exceptions.FachdienstException;
import de.gematik.idp.fachdienst.services.ClientAssertionBuilder;
import de.gematik.idp.fachdienst.services.EntityStmntIdpsService;
import de.gematik.idp.fachdienst.services.FachdienstAuthenticator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Map.Entry;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Pattern;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Validated
@RequiredArgsConstructor
@Slf4j
public class AuthorizationController {

    private static final int MAX_AUTH_SESSION_AMOUNT = 10000;
    private static final int FACHDIENST_STATE_LENGTH = 32;
    private static final int FACHDIENST_NONCE_LENGTH = 32;
    private final FachdienstAuthenticator fachdienstAuthenticator;
    private final ServerUrlService serverUrlService;
    private final EntityStmntIdpsService entityStmntIdpsService;
    private final ClientAssertionBuilder clientAssertionBuilder;
    private final IdpJwtProcessor jwtProcessor;
    private final ObjectMapper objectMapper;

    private final Map<String, FachdienstAuthSession> fachdienstAuthSessions = new LinkedHashMap<>() {

        @Override
        protected boolean removeEldestEntry(final Entry<String, FachdienstAuthSession> eldest) {
            return size() > MAX_AUTH_SESSION_AMOUNT;
        }
    };


    /* Federation App2App flow
     * Request(in)  == message nr.1
     *                 messages nr.1a ... nr.2b
     * Response(out)== message nr.4
     */
    @GetMapping(value = FACHDIENST_AUTHORIZATION_ENDPOINT)
    public void getRequestUri(
        @RequestParam(name = "client_id") @NotEmpty final String frontendClientId,
        @RequestParam(name = "state") @NotEmpty final String frontendState,
        @RequestParam(name = "redirect_uri") @NotEmpty final String frontendRedirectUri,
        @RequestParam(name = "code_challenge") @NotEmpty final String frontendCodeChallenge,
        @RequestParam(name = "code_challenge_method") @NotEmpty @Pattern(regexp = "S256") final String frontendCodeChallengeMethod,
        @RequestParam(name = "response_type") @NotEmpty @Pattern(regexp = "code") final String responseType,
        @RequestParam(name = "scope") @NotEmpty @Pattern(regexp = "e-rezept") final String scope,
        @RequestParam(name = "idp_iss") @NotEmpty final String idpIss,
        final HttpServletRequest requestMsgNr1,
        final HttpServletResponse respMsgNr4) {

        final String fachdienstServerUrl = serverUrlService.determineServerUrl(requestMsgNr1);
        final String fachdienstState = new Nonce().getNonceAsHex(FACHDIENST_STATE_LENGTH);
        final String fachdienstNonce = new Nonce().getNonceAsHex(FACHDIENST_NONCE_LENGTH);
        final String fachdienstCodeVerifier = generateCodeVerifier(); // top secret
        final String fachdienstCodeChallenge = generateCodeChallenge(fachdienstCodeVerifier);

        log.info("Amount of stored fachdienstAuthSessions: {}", fachdienstAuthSessions.size());

        fachdienstAuthSessions.put(fachdienstState, FachdienstAuthSession.builder()
            .frontendClientId(frontendClientId)
            .frontendCodeChallenge(frontendCodeChallenge)
            .frontendCodeChallengeMethod(frontendCodeChallengeMethod)
            .frontendState(frontendState)
            .frontendRedirektUri(frontendRedirectUri)
            .fachdienstCodeverifier(fachdienstCodeVerifier)
            .build()
        );

        final String sekIdpAuthEndpoint = getSekIdpAuthEndpointFromEntityStmnt(idpIss);
        /*
         * Request(out) == message nr.2
         * Response(in) == message nr.3
         */
        final HttpResponse<JsonNode> respMsgNr3 = Unirest.get(sekIdpAuthEndpoint)
            .queryString("client_id", fachdienstServerUrl)
            .queryString("state", fachdienstState)
            .queryString("redirect_uri", fachdienstServerUrl + FACHDIENST_AUTHORIZATION_ENDPOINT)
            .queryString("code_challenge", fachdienstCodeChallenge)
            .queryString("code_challenge_method", "S256")
            .queryString("response_type", "code")
            .queryString("nonce", fachdienstNonce)
            .queryString("scope", "erp_sek_auth+openid")
            .queryString("acr_values", "TODO")
            .queryString("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            .queryString("client_assertion", createClientAssertion(serverUrlService.determineServerUrl(requestMsgNr1),
                sekIdpAuthEndpoint))
            .queryString("claims", "TODO")
            .asJson();

        final String requestUri;
        try {
            // ParResponse example: {"request_uri":"urn:http://127.0.0.1:8084:4434f963244b9f0f","expires_in":90}
            final ParResponse p = new ObjectMapper().readValue(respMsgNr3.getBody().toString(), ParResponse.class);
            requestUri = p.getRequestUri();
        } catch (final JsonProcessingException e) {
            throw new FachdienstException("request_uri not found", e);
        }

        respMsgNr4.setStatus(HttpStatus.FOUND.value());
        // message nr.4
        setNoCacheHeader(respMsgNr4);
        final String tokenLocation = fachdienstAuthenticator.createLocationForAuthorizationRequest(sekIdpAuthEndpoint,
            fachdienstServerUrl, requestUri);
        respMsgNr4.setHeader(HttpHeaders.LOCATION, tokenLocation);
    }

    private String createClientAssertion(final String serverUrl, final String sekIdpAuthEndpoint) {
        return JwtHelper.signJson(jwtProcessor, objectMapper,
            clientAssertionBuilder.buildClientAssertion(serverUrl, sekIdpAuthEndpoint));
    }

    private static void setNoCacheHeader(final HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
    }

    private String getSekIdpAuthEndpointFromEntityStmnt(final String idpIss) {
        return entityStmntIdpsService.getAuthorizationEndpoint(
            entityStmntIdpsService.getEntityStatement(idpIss)
        );
    }

}
