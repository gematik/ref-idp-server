/*
 * Copyright (c) 2021 gematik GmbH
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

package de.gematik.idp.server;

import static de.gematik.idp.authentication.UriUtils.extractParameterMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.IdpJoseObject;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import de.gematik.idp.token.TokenClaimExtraction;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.Key;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.crypto.spec.SecretKeySpec;
import kong.unirest.*;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Slf4j
public class TokenLoggerTest {

    private final static Map<String, Function<Object, Object>> MASKING_FUNCTIONS = new HashMap<>();
    private static final int MAX_STRING_LENGHT = 50;
    private static final int CUT_STRING_LENGTH = 20;
    private static final String CODE_SEPERATOR = "\n```\n";
    @Autowired
    private IdpConfiguration idpConfiguration;
    @Autowired
    private IdpKey idpSig;
    @Autowired
    private IdpKey idpEnc;
    @Autowired
    private Key symmetricEncryptionKey;
    private IdpClient idpClient;
    private PkiIdentity egkUserIdentity;
    @LocalServerPort
    private int localServerPort;
    private File tokenLogFile;
    private Gson gson;

    {
        MASKING_FUNCTIONS.put("exp", value -> "<Gültigkeit des Tokens von " + formatToHumanReadable(
            Duration.between(ZonedDateTime.now(), TokenClaimExtraction.claimToZonedDateTime(value)))
            + ". Beispiel: '" + value.toString() + "'>");
        MASKING_FUNCTIONS
            .put("iat", value -> "<Zeitpunkt der Ausstellung des Tokens. Beispiel: '" + value.toString() + "'>");
        MASKING_FUNCTIONS
            .put("nbf",
                value -> "<Der Token ist erst ab diesem Zeitpunkt gültig. Beispiel: '" + value.toString() + "'>");

        MASKING_FUNCTIONS.put("code_challenge",
            v -> "<code_challenge value, Base64URL(SHA256(code_verifier)). Beispiel: " + v.toString() + ">");

        MASKING_FUNCTIONS.put("nonce", v ->
            "<String value used to associate a Client session with an ID Token, and to mitigate replay attacks. Beispiel: '"
                + v.toString() + "'>");

        MASKING_FUNCTIONS.put("state",
            v -> "<OAuth 2.0 state value. Constant over complete flow. Value is a case-sensitive string. Beispiel: '"
                + v.toString() + "'>");

        MASKING_FUNCTIONS.put("jti", v ->
            "<A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string. Beispiel: '"
                + v.toString() + "'>");

        MASKING_FUNCTIONS.put("given_name",
            v -> "<'givenName' aus dem subject-DN des authentication-Zertifikats. Beispiel: '" + v.toString() + "'>");
        MASKING_FUNCTIONS.put("family_name",
            v -> "<'surname' aus dem subject-DN des authentication-Zertifikats. Beispiel: '" + v.toString() + "'>");
        MASKING_FUNCTIONS.put("idNummer",
            v -> "<KVNR oder Telematik-ID aus dem authentication-Zertifikats. Beispiel: '" + v.toString() + "'>");
        MASKING_FUNCTIONS.put("professionOID",
            v -> "<professionOID des HBA aus dem authentication-Zertifikats. Null if not present. Beispiel: '" +
                v.toString() + "'>");
        MASKING_FUNCTIONS.put("organizationName",
            v -> "<professionOID des HBA  aus dem authentication-Zertifikats. Null if not present. Beispiel: '" +
                v.toString() + "'>");
        MASKING_FUNCTIONS.put("auth_time",
            v ->
                "<timestamp of authentication. Technically this is the time of authentication-token signing. Beispiel: '"
                    + v.toString() + "'>");
        MASKING_FUNCTIONS.put("snc",
            v -> "<server-nonce. Used to introduce noise. Beispiel: '" + v.toString() + "'>");
        MASKING_FUNCTIONS.put("cnf",
            v -> "<confirmation. Authenticated certificate of the client. For details see rfc7800. Beispiel: '" +
                prettyPrintJsonString(v.toString(), " ".repeat(60)) + "'>");
        MASKING_FUNCTIONS.put("sub",
            v -> "<subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt)). Beispiel: '" +
                v.toString() + "'>");
        MASKING_FUNCTIONS.put("at_hash",
            v ->
                "<Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16)). Beispiel: '"
                    + v.toString() + "'>");
        MASKING_FUNCTIONS.put("x5c",
            v -> "<Enthält das verwendete Signer-Zertifikat. Beispiel: '" + prettyPrintJsonString(v.toString(),
                " ".repeat(60)) + "'>");

        MASKING_FUNCTIONS.put("authorization_endpoint", v -> "<URL des Authorization Endpunkts.>");
        MASKING_FUNCTIONS.put("sso_endpoint", v -> "<URL des Authorization Endpunkts.>");
        MASKING_FUNCTIONS.put("token_endpoint", v -> "<URL des Authorization Endpunkts.>");
        MASKING_FUNCTIONS.put("uri_disc", v -> "<URL des Discovery-Dokuments>");
        MASKING_FUNCTIONS.put("puk_uri_auth", v -> "<URL einer JWK-Struktur des Authorization Public-Keys>");
        MASKING_FUNCTIONS.put("puk_uri_token", v -> "<URL einer JWK-Struktur des Token Public-Keys>");
        MASKING_FUNCTIONS.put("jwks_uri", v -> "<URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln>");
        MASKING_FUNCTIONS.put("njwt", v -> "<enthält das Ursprüngliche Challenge Token des Authorization Endpunkt>");
        MASKING_FUNCTIONS.put("Location", v -> formatUrl(v.toString()));
        MASKING_FUNCTIONS.put("Date", v -> "<Zeitpunkt der Antwort. Beispiel '" + v + "'>");
    }

    @BeforeEach
    public void startup(
        @PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity)
        throws IOException {
        idpClient = IdpClient.builder()
            .clientId(IdpConstants.CLIENT_ID)
            .discoveryDocumentUrl("http://localhost:" + localServerPort + IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT)
            .redirectUrl(idpConfiguration.getRedirectUri())
            .build();

        idpClient.initialize();

        egkUserIdentity = PkiIdentity.builder()
            .certificate(clientIdentity.getCertificate())
            .privateKey(clientIdentity.getPrivateKey())
            .build();

        createTokenLogFile();

        gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();
    }

    @SneakyThrows
    @AfterEach
    public void copyTokenFlowToTarget() {
        final String filename = idpConfiguration.getTokenFlowMdResource().replace("classpath:", "");
        final java.nio.file.Path copied = Paths.get("target/classes/" + filename);
        final java.nio.file.Path originalPath = tokenLogFile.toPath();
        Files.copy(originalPath, copied, StandardCopyOption.REPLACE_EXISTING);
    }

    @Test
    public void writeAllTokensToFile() {
        // Authorization Request
        idpClient
            .setBeforeAuthorizationCallback(getRequest -> appendRequestToFile("Authorization Request", getRequest));

        // Challenge Token
        idpClient.setAfterAuthorizationCallback(response -> {
            appendResponseToFile("Authorization Response", response);

            appendTokenToFile("Challenge Token", response.getBody().getChallenge());
        });

        // Authentication Request
        idpClient
            .setBeforeAuthenticationCallback(getRequest -> {
                    appendRequestToFile("Authentication Request", getRequest);

                    appendMultipartAndDecrypt(getRequest.getBody().get().multiParts(), "signed_challenge",
                        "Challenge Response", idpEnc.getIdentity().getPrivateKey());
                    appendMultipartAndDecrypt(getRequest.getBody().get().multiParts(), "sso_token",
                        "SSO Token", symmetricEncryptionKey);
                    appendMultipartAndDecrypt(getRequest.getBody().get().multiParts(), "unsigned_challenge",
                        "Unsigned Challenge", null);
                }
            );

        // Authorization Code
        idpClient.setAfterAuthenticationCallback(response -> {
                appendResponseToFile("Authentication Response", response);
                final Map<String, String> parameterMap = extractParameterMap(response.getHeaders().getFirst("Location"));

                if (parameterMap.containsKey("code")) {
                    appendJwe(new IdpJwe(parameterMap.get("code")), "Authorization Code", symmetricEncryptionKey);
                }

                if (parameterMap.containsKey("sso_token")) {
                    appendJwe(new IdpJwe(parameterMap.get("sso_token")), "SSO Token", symmetricEncryptionKey);
                }
            }
        );

        final AtomicReference<Key> clientTokenKey = new AtomicReference<>();

        // Token Request
        idpClient.setBeforeTokenCallback(getRequest -> {
                appendRequestToFile("Token Request", getRequest);
                final IdpJwe keyVerifier = getRequest.getBody().get().multiParts().stream()
                    .filter(p -> p.getName().equals("key_verifier"))
                    .map(p -> new IdpJwe(p.getValue().toString()))
                    .findAny().get();

                appendTokenToFile("Key verifier (Encryption Header)", keyVerifier);
                keyVerifier.setDecryptionKey(idpEnc.getIdentity().getPrivateKey());

                appendToFile(
                    "Key verifier (Body)\n\n" + CODE_SEPERATOR + prettyPrintJsonString(
                        gson.toJson(keyVerifier.getBodyClaims()), "") + CODE_SEPERATOR + "\n");
                clientTokenKey.set(new SecretKeySpec(
                    Base64.getUrlDecoder().decode(keyVerifier.getStringBodyClaim(ClaimName.TOKEN_KEY).get()),
                    "AES"));
            }
        );

        idpClient.setAfterTokenCallback(response -> {
            appendResponseToFile("Token Response", response);

            final JSONObject responseObject = response.getBody().getObject();
            final IdpJwe accessToken = new IdpJwe(responseObject.getString("access_token"));
            appendTokenToFile("Access Token (Encryption Header)", accessToken);
            appendTokenToFile("Access Token (Decrypted)", accessToken.decryptNestedJwt(clientTokenKey.get()));

            final IdpJwe idToken = new IdpJwe(responseObject.getString("id_token"));
            appendTokenToFile("ID Token (Encryption Header)", idToken);
            appendTokenToFile("ID Token (Decrypted)", idToken.decryptNestedJwt(clientTokenKey.get()));
        });
        addSeperator("# Basic FLOW", "=");
        appendToFile("Log-In attempt using egk with DN '"
            + egkUserIdentity.getCertificate().getSubjectX500Principal().toString() + "'\n\n\n");

        final IdpJwe ssoToken = idpClient.login(egkUserIdentity).getSsoToken();

        addSeperator("# SSO Flow", "=");

        idpClient.loginWithSsoToken(ssoToken);

        // Discovery Document
        final String ddRaw = Unirest.get(idpClient.getDiscoveryDocumentUrl()).asString().getBody();

        addSeperator("# Discovery Document", "=");
        appendTokenToFile("", new JsonWebToken(ddRaw));
    }

    private void appendMultipartAndDecrypt(
        final Collection<BodyPart> bodyParts, final String parameter_name, final String tokenName,
        final Key decryptionKey) {
        bodyParts
            .stream()
            .filter(bodyPart -> bodyPart.getName().equals(parameter_name))
            .map(BodyPart::getValue)
            .findAny()
            .map(Object::toString)
            .ifPresent(tokenString -> {
                if (decryptionKey != null) {
                    appendJwe(new IdpJwe(tokenString), tokenName, decryptionKey);
                } else {
                    appendTokenToFile(tokenName, new JsonWebToken(tokenString));
                }
            });
    }

    private void appendJwe(final IdpJwe token, final String tokenName, final Key decryptionKey) {
        appendTokenToFile(tokenName + " (Encryption Header)", token);
        appendTokenToFile(tokenName + " (Decrypted)", token.decryptNestedJwt(decryptionKey));
    }

    private void createTokenLogFile() throws IOException {
        tokenLogFile = new File("src/main/resources/" +
            idpConfiguration.getTokenFlowMdResource().replace("classpath:", ""));
        if (tokenLogFile.isFile()) {
            tokenLogFile.delete();
        }
        tokenLogFile.createNewFile();
    }

    private void appendRequestToFile(final String name, final HttpRequest<?> request) {
        addSeperator("## " + name, ">");
        final String multipartBody = request.getBody().map(
            body -> body.multiParts().stream()
                .map(part -> part.getName() + "=" + part.getValue())
                .collect(Collectors.joining("\n", "Multiparts:\n", "\n")))
            .orElse("");
        appendToFile(CODE_SEPERATOR + formatUrl(request.getUrl()) + "\n" + multipartBody + CODE_SEPERATOR + "\n");
    }

    @SneakyThrows
    private String formatUrl(final String url) {
        final URI uri = new URI(url);
        final Map<String, String> pathMapping = Map.of(
            IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT, "<URI_DISC>",
            IdpConstants.BASIC_AUTHORIZATION_ENDPOINT, "<AUTHORIZATION_ENDPOINT>",
            IdpConstants.SSO_ENDPOINT, "<SSO_ENDPOINT>",
            IdpConstants.TOKEN_ENDPOINT, "<TOKEN_ENDPOINT>"
        );

        final String query = formatQueryString(uri);
        return "https://<FQDN Server>/"
            + pathMapping.getOrDefault(uri.getPath(), uri.getPath())
            + query;
    }

    private String formatQueryString(final URI uri) {
        if (StringUtils.isEmpty(uri.getQuery())) {
            return "";
        }

        return Stream.of(uri.getQuery().split("&"))
            .map(q -> {
                final String[] split = q.split("=");
                if (MASKING_FUNCTIONS.containsKey(split[0])) {
                    return split[0] + "=" + MASKING_FUNCTIONS.get(split[0])
                        .apply(split[1]);
                } else {
                    return q;
                }
            })
            .collect(Collectors.joining("\n    &", "\n    ?", ""));
    }

    private void addSeperator(final String title, final String seperatorString) {
        appendToFile(title + " \n");
    }

    private void appendResponseToFile(final String name, final HttpResponse<?> response) {
        addSeperator("## " + name, "<");
        appendToFile(CODE_SEPERATOR + response.getStatus() + "\n" + response.getHeaders()
            .all().stream()
            .map(header -> {
                if (header.getName().equals("Location")) {
                    return Pair.of("Location", formatUrl(header.getValue()));
                } else if (MASKING_FUNCTIONS.containsKey(header.getName())) {
                    return Pair.of(header.getName(), MASKING_FUNCTIONS.get(header.getName()).apply(header.getValue()));
                } else {
                    return Pair.of(header.getName(), header.getValue());
                }
            })
            .map(header -> header.getKey() + "=" + header.getValue())
            .collect(Collectors.joining(",\n")) + CODE_SEPERATOR + extractBodyFromResponse(response) + "\n\n");
    }

    private String extractBodyFromResponse(final HttpResponse<?> response) {
        if (response.getBody().toString().isEmpty()) {
            return "";
        }
        return "\n\nResponse-Body:\n" + CODE_SEPERATOR + mapBodyToString(response.getBody()) + CODE_SEPERATOR;
    }

    private String mapBodyToString(final Object body) {
        if (body instanceof AuthenticationChallenge) {
            return gson.toJson(body);
        } else if (body instanceof JsonNode) {
            return ((JsonNode) body).toPrettyString();
        } else if (body instanceof String) {
            return body.toString();
        } else {
            return "Ugly-printing " + body.getClass().getSimpleName() + ": \n\n'" + body.toString() + "'";
        }
    }

    private void appendTokenToFile(final String tokenName, final IdpJoseObject token) {
        final String prettyPrintendTokenParts = prettyPrintJoseParts(token.getRawString());
        final String intro = tokenName.isBlank() ? "" : "### " + tokenName + ":\n";
        appendToFile(intro + CODE_SEPERATOR + prettyPrintendTokenParts + CODE_SEPERATOR + "\n\n");
    }

    private String prettyPrintJoseParts(final String tokenString) {
        return Stream.of(tokenString.split("\\."))
            .map(Base64.getUrlDecoder()::decode)
            .map(String::new)
            .filter(StringUtils::isNotBlank)
            .map(str -> {
                try {
                    return Optional.of(new JsonNode(str));
                } catch (final Exception e) {
                    return Optional.empty();
                }
            })
            .filter(Optional::isPresent)
            .map(Optional::get)
            .map(JsonNode.class::cast)
            .map(this::maskVariableParts)
            .map(JsonNode::toPrettyString)
            .map(StringEscapeUtils::unescapeJava)
            .collect(Collectors.joining("\n"));
    }

    private String prettyPrintJsonString(final String value, final String newLineFiller) {
        final JsonNode jsonNode = new JsonNode(value);
        cutStrings(jsonNode);
        final String cleanString = StringEscapeUtils.unescapeJava(jsonNode.toPrettyString());
        return cleanString.replace("\n", "\n" + newLineFiller);
    }

    private void cutStrings(final JsonNode jsonNode) {
        if (jsonNode == null) {
            return;
        }
        cutStrings(jsonNode.getObject());
        cutStrings(jsonNode.getArray());
    }

    private void cutStrings(final JSONArray array) {
        if (array == null) {
            return;
        }
        for (int i = 0; i < array.length(); i++) {
            final Object value = cutStrings(array.get(i));
            if (value != null) {
                array.put(i, value);
            }
        }
    }

    private void cutStrings(final JSONObject object) {
        if (object == null) {
            return;
        }
        for (final String key : object.keySet()) {
            final Object value = cutStrings(object.get(key));
            if (value != null) {
                object.put(key, value);
            }
        }
    }

    private Object cutStrings(final Object o) {
        if (o == null) {
            return null;
        }
        if (o instanceof JsonNode) {
            cutStrings((JsonNode) o);
        } else if (o instanceof JSONArray) {
            cutStrings((JSONArray) o);
        } else if (o instanceof JSONObject) {
            cutStrings((JSONObject) o);
        } else if (o instanceof String) {
            if (((String) o).length() > MAX_STRING_LENGHT) {
                return ((String) o).substring(0, CUT_STRING_LENGTH) + "...";
            }
        } else {
            System.out.println("unknown: " + o.getClass().getSimpleName() + " => " + o);
        }
        return null;
    }

    private JsonNode maskVariableParts(final JsonNode jsonNode) {
        final JSONObject object = jsonNode.getObject();

        final List<String> keys = object.keySet().stream().collect(Collectors.toList());
        keys.stream().forEach(key -> {
            if (MASKING_FUNCTIONS.containsKey(key)) {
                object.put(key, MASKING_FUNCTIONS
                    .get(key)
                    .apply(object.get(key)));
            }
        });
        return jsonNode;
    }

    private String formatToHumanReadable(final Duration input) {
        final Duration duration = input
            .withNanos(0)
            .plusMinutes(input.toSecondsPart() > 30 ? 1 : 0)
            .minusSeconds(input.toSecondsPart());
        if (duration.minusMinutes(59).isNegative()) {
            return duration.toMinutes() + " Minuten";
        }
        if (duration.minusHours(23).isNegative()) {
            return duration.toHours() + " Stunden";
        }
        return duration.toString();
    }

    private void appendToFile(final String content) {
        try {
            FileUtils.writeStringToFile(tokenLogFile, content, StandardCharsets.UTF_8, true);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }
}
