/*
 * Copyright (c) 2021 gematik GmbH
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

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.test.steps.helpers.IdpTestEnvironmentConfigurator;
import de.gematik.idp.test.steps.helpers.JsonChecker;
import de.gematik.idp.test.steps.model.CodeAuthType;
import de.gematik.idp.test.steps.model.DiscoveryDocument;
import de.gematik.idp.test.steps.model.HttpMethods;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import de.gematik.test.bdd.ThreadedContextProvider;
import io.restassured.response.Response;
import java.net.URISyntaxException;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.time.chrono.ChronoZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.assertj.core.api.Assertions;
import org.jetbrains.annotations.NotNull;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.json.JSONObject;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

@Slf4j
public class IdpAuthorizationSteps extends IdpStepsBase {

    private final JsonChecker jsoncheck = new JsonChecker();

    @SneakyThrows
    public void signChallenge(final String keyfile, final String password) {
        final String challenge = Context.get().getString(ContextKey.CHALLENGE);

        final Key pkey = keyAndCertificateStepsHelper.readPrivateKeyFromKeyStore(keyfile, password);
        final X509Certificate cert = keyAndCertificateStepsHelper.readCertFrom(keyfile, password);

        final JSONObject claims = new JSONObject();
        claims.put("njwt", challenge);
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(claims.toString());
        jsonWebSignature.setKey(pkey);
        if (cert.getPublicKey().getAlgorithm().equals("EC")) {
            jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
        } else {
            jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_PSS_USING_SHA256);
        }
        jsonWebSignature.setHeader("typ", "JWT");
        jsonWebSignature.setHeader("cty", "NJWT");
        jsonWebSignature.setCertificateChainHeaderValue(cert);

        Context.get().putString(ContextKey.SIGNED_CHALLENGE, jsonWebSignature.getCompactSerialization());
    }

    public void getCode(final CodeAuthType authType, final HttpStatus expectedStatus)
        throws URISyntaxException {
        final ThreadedContextProvider ctxt = Context.get();
        final Map<String, String> params = new HashMap<>();
        final String path = checkParamsNGetPath(authType, params);
        final Response r = requestResponseAndAssertStatus(
            path, null, HttpMethods.POST,
            params, null, expectedStatus);

        ctxt.put(ContextKey.RESPONSE, r);
        final HttpStatus responseStatus = new HttpStatus(r.getStatusCode());

        String error = null;
        if (responseStatus.getValue() == 302) {
            final String loc = getLocationHeader(r);
            error = new URIBuilder(loc).getQueryParams().stream()
                .filter(param -> param.getName().equalsIgnoreCase("error"))
                .map(NameValuePair::getValue)
                .findFirst()
                .orElse(null);
        } else if (responseStatus.isError()) {
            error = "Error " + responseStatus.getValue();
        }
        if (error == null) {
            storeResponseContentInContext(authType, ctxt.getMapForCurrentThread(), r);
        } else {
            ctxt.put(ContextKey.TOKEN_REDIRECT_URL, null);
            ctxt.put(ContextKey.TOKEN_CODE, null);
            ctxt.put(ContextKey.TOKEN_CODE_ENCRYPTED, null);
            ctxt.put(ContextKey.STATE, null);
            if (authType == CodeAuthType.SSO_TOKEN) {
                ctxt.put(ContextKey.SSO_TOKEN, null);
                ctxt.put(ContextKey.SSO_TOKEN_ENCRYPTED, null);
            }
        }
    }

    @SneakyThrows
    private String checkParamsNGetPath(final CodeAuthType authType, final Map<String, String> params) {
        String path = Context.getDiscoveryDocument().getAuthorizationEndpoint();
        switch (authType) {
            case SIGNED_CHALLENGE:
                checkContextAddToParams(ContextKey.SIGNED_CHALLENGE, "signed_challenge", params);
                // encrypt signed challenge
                final Optional<Pair<String, Object>> expHeader = extractExpHeader(params.get("signed_challenge"));
                if (expHeader.isPresent()) {
                    params.put("signed_challenge",
                        keyAndCertificateStepsHelper
                            .encrypt("{\"njwt\":\"" + params.get("signed_challenge") + "\"}",
                                DiscoveryDocument.getPublicKeyFromContextKey(ContextKey.PUK_ENC), expHeader.get()));
                } else {
                    params.put("signed_challenge",
                        keyAndCertificateStepsHelper
                            .encrypt("{\"njwt\":\"" + params.get("signed_challenge") + "\"}",
                                DiscoveryDocument.getPublicKeyFromContextKey(ContextKey.PUK_ENC)));
                }
                break;
            case SSO_TOKEN:
                checkContextAddToParams(ContextKey.CHALLENGE, "unsigned_challenge", params);
                checkContextAddToParams(ContextKey.SSO_TOKEN_ENCRYPTED, "ssotoken", params);
                path = Context.getDiscoveryDocument().getSsoEndpoint();
                break;
            case SSO_TOKEN_NO_CHALLENGE:
                checkContextAddToParams(ContextKey.SSO_TOKEN_ENCRYPTED, "ssotoken", params);
                path = Context.getDiscoveryDocument().getSsoEndpoint();
                break;
            case SIGNED_CHALLENGE_WITH_SSO_TOKEN:
                checkContextAddToParams(ContextKey.CHALLENGE, "unsigned_challenge", params);
                checkContextAddToParams(ContextKey.SSO_TOKEN_ENCRYPTED, "ssotoken", params);
                break;
            case ALTERNATIVE_AUTHENTICATION:
                checkContextAddToParams(ContextKey.SIGEND_AUTHENTICATION_DATA, "encrypted_signed_authentication_data",
                    params);
                // encrypt signed challenge
                params.put(
                    "encrypted_signed_authentication_data",
                    keyAndCertificateStepsHelper
                        .encrypt("{\"njwt\":\"" + params.get("encrypted_signed_authentication_data") + "\"}",
                            DiscoveryDocument.getPublicKeyFromContextKey(ContextKey.PUK_ENC),
                            Pair.of("cty", "NJWT"),
                            Pair.of("typ", "JWT"),
                            extractExpHeader(params.get("encrypted_signed_authentication_data"))
                                .or(() -> extractExpForAltAuthChallenge(params))
                                .orElse(Pair.of("exp", ZonedDateTime.now().plusMinutes(30).toEpochSecond()))));
                path = Context.getDiscoveryDocument().getAltAuthEndpoint();
                break;
            case THIRD_PARTY_AUTHORIZATION_CODE:
                path = Context.getDiscoveryDocument().getThirdPartyEndpoint();
                final String location = getLocationHeader(Context.getCurrentResponse());
                final Map<String, String> parameters = UriComponentsBuilder.fromUriString(location).build()
                    .getQueryParams().toSingleValueMap();
                assertThat(parameters).containsKey("code").containsKey("state");
                params.put("code", parameters.get("code"));
                params.put("state", parameters.get("state"));
                //TODO: dieser parameter muss aus einer config datei kommen oder so
                params.put("kk_app_redirect_uri", "https://kk.dev.gematik.solutions");
                break;
        }
        return path;
    }

    @NotNull
    private Optional<Pair<String, Object>> extractExpForAltAuthChallenge(final Map<String, String> params) {
        try {
            return new JsonWebToken(params.get("encrypted_signed_authentication_data"))
                .getNestedJwtForClaimName(ClaimName.CHALLENGE_TOKEN)
                .flatMap(JsonWebToken::findExpClaimInNestedJwts)
                .map(ChronoZonedDateTime::toEpochSecond)
                .map(expValue -> Pair.of("exp", expValue));
        } catch (final Exception e) {
            return Optional.empty();
        }
    }

    private Optional<Pair<String, Object>> extractExpHeader(final String signedChallenge) {
        try {
            return new JsonWebToken(signedChallenge).findExpClaimInNestedJwts()
                .map(ChronoZonedDateTime::toEpochSecond)
                .map(epoch -> Pair.of(ClaimName.EXPIRES_AT.getJoseName(), epoch));
        } catch (final Exception e) {
            return Optional.empty();
        }
    }

    @SneakyThrows
    private void storeResponseContentInContext(
        final CodeAuthType authType, final Map<String, Object> ctxt, final Response r) {
        final String reloc = getLocationHeader(r);
        assertThat(reloc).withFailMessage("No Location header in response", r.getHeaders()).isNotBlank();

        ctxt.put(ContextKey.TOKEN_REDIRECT_URL, reloc);

        // if token encryption active decrypt code and store it in context
        final Optional<String> encTokenCode = storeParamOfReloc(reloc, "code", ContextKey.TOKEN_CODE_ENCRYPTED);
        assertThat(encTokenCode).withFailMessage("Encrypted token code not found").isPresent();
        final CodeAuthType tokenSecret = authType == CodeAuthType.ALTERNATIVE_AUTHENTICATION
            ? CodeAuthType.ALTERNATIVE_AUTHENTICATION
            : CodeAuthType.SIGNED_CHALLENGE;

        try {
            if (encTokenCode.isPresent()) {
                Context.get().put(
                    ContextKey.TOKEN_CODE,
                    keyAndCertificateStepsHelper.decryptAndExtractNjwt(
                        encTokenCode.get(),
                        IdpTestEnvironmentConfigurator.getSymmetricEncryptionKey(tokenSecret))
                );
            } else {
                Assertions.fail("No encrypted token code in relocation header!");
            }
        } catch (final Exception e) {
            log.error("Unable to decode encrypted token code!", e);
        }

        storeParamOfReloc(reloc, "state", ContextKey.STATE);
        if (authType != CodeAuthType.SSO_TOKEN) {
            // if token encryption active decrypt sso token and store in context
            final Optional<String> encSsoToken = storeParamOfReloc(reloc, "ssotoken",
                ContextKey.SSO_TOKEN_ENCRYPTED);
            try {
                Context.get().put(
                    ContextKey.SSO_TOKEN,
                    encSsoToken
                        .map(s -> keyAndCertificateStepsHelper
                            .decryptAndExtractNjwt(s,
                                IdpTestEnvironmentConfigurator.getSymmetricEncryptionKey(CodeAuthType.SSO_TOKEN)))
                        .orElse(null)
                );
            } catch (final Exception e) {
                log.error("Unable to decode encrypted sso token!", e);
            }
        } else {
            ctxt.put(ContextKey.SSO_TOKEN, null);
            ctxt.put(ContextKey.SSO_TOKEN_ENCRYPTED, null);
        }
    }

    private Optional<String> storeParamOfReloc(final String reloc, final String paramName, final String key)
        throws URISyntaxException {
        final Optional<String> value = new URIBuilder(reloc).getQueryParams().stream()
            .filter(param -> param.getName().equalsIgnoreCase(paramName))
            .map(NameValuePair::getValue)
            .findFirst();

        if (Optional.of(paramName)
            .filter(param -> !param.equals("ssotoken") || value.isPresent())
            .isPresent()) {
            assertThat(value)
                .withFailMessage("Expected relocation query param " + paramName + " to be not blank")
                .isNotEmpty();
        }

        Context.get().put(key, value.orElse(null));
        return value;
    }

    private void checkContextAddToParams(final String key, final String paramName,
        final Map<String, String> params) {
        assertThat(Context.get().getMapForCurrentThread()).containsKey(key).doesNotContainEntry(key, null);
        params.put(paramName, String.valueOf(Context.get().get(key)));
    }

    public void responseIsErrorWithMessageMatching(final int httpStatus, final int errid, final String errcode) {
        final Response r = Context.getCurrentResponse();
        assertThat(r.getStatusCode()).isEqualTo(httpStatus);
        if (httpStatus == 302) {
            final String location = getLocationHeader(r);
            final MultiValueMap<String, String> parameters = UriComponentsBuilder.fromUriString(location).build()
                .getQueryParams();

            // TODO RISE deliver error attribute  //TODO REF eventually make error attribute optional
            assertThat(parameters)
                .containsKeys("error", "gematik_error_text", "gematik_timestamp", "gematik_uuid",
                    "gematik_code");
            final String returnedErrCode = parameters.getFirst("error");
            if (!errcode.equals(returnedErrCode)) {
                assertThat(returnedErrCode).matches(errcode);
            }
            assertThat(parameters.getFirst("gematik_code")).isEqualTo(String.valueOf(errid));

            // TODO Clarify if state should be also sent with errors
        } else {
            jsoncheck.assertJsonShouldMatchInAnyOrder(Context.getCurrentResponse().getBody().asString(),
                " { ____error:              \"" + errcode + "\",\n"
                    + "\t        gematik_error_text: \".*\",\n"
                    + "\t        gematik_timestamp:  \"[\\\\d]*\",\n"
                    + "\t        gematik_uuid:       \".*\",\n"
                    + "\t        gematik_code:       \"" + errid + "\"\n"
                    + "          }");
        }
    }
}
