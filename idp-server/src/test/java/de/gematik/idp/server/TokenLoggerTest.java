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

import static de.gematik.idp.authentication.UriUtils.extractParameterValue;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.client.IdpTokenResult;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.stream.Collectors;
import kong.unirest.BodyPart;
import kong.unirest.HttpRequest;
import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.io.FileUtils;
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
public class TokenLoggerTest {

    @Autowired
    private IdpConfiguration idpConfiguration;
    @Autowired
    private IdpKey authKey;
    private IdpClient idpClient;
    private PkiIdentity egkUserIdentity;
    @LocalServerPort
    private int localServerPort;
    private File tokenLogFile;

    private static String jwtToJson(final String jwt) {

        final JsonNode jwtHeader = new JsonNode(
            StringUtils.newStringUtf8(Base64.getDecoder().decode(jwt.split("\\.")[0])));
        final JsonNode jwtBody = new JsonNode(
            StringUtils.newStringUtf8(Base64.getDecoder().decode(jwt.split("\\.")[1])));
        return jwtHeader.toPrettyString() + "\n" + jwtBody.toPrettyString();
    }

    @BeforeEach
    public void startup(@PkiKeyResolver.Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity clientIdentity)
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

        tokenLogFile = createTokenLogFile();
    }

    @Test
    public void writeAllTokensToFile() {
        // Authorization Request
        idpClient.setBeforeAuthorizationCallback(getRequest -> appendRequestToFile(
            tokenLogFile, "Authorization Request", getRequest));

        // Challenge Token
        idpClient.setAfterAuthorizationCallback(response -> {
            appendResponseToFile(tokenLogFile, "Authorization Response", response);

            appendTokenToFile(
                tokenLogFile, "Challenge Token", response.getBody().getChallenge() + "\n" +
                    jwtToJson(response.getBody().getChallenge().getJwtRawString()));
        });

        // Challenge Response Token
        idpClient.setBeforeAuthenticationCallback(mb -> mb.getBody().get().multiParts().stream()
            .filter(bodyPart -> bodyPart.getName().equals("signed_challenge"))
            .map(BodyPart::getValue)
            .findAny()
            .map(Object::toString)
            .map(IdpJwe::new)
            .map(jwe -> jwe.decrypt(authKey.getIdentity().getPrivateKey()))
            .map(JsonWebToken::getJwtRawString)
            .ifPresent(o -> appendTokenToFile(tokenLogFile, "Challenge Response Token",
                o.toString() + "\n" + jwtToJson(o.toString())))
        );

        // Authorization Code
        idpClient.setAfterAuthenticationCallback(response -> {
                appendResponseToFile(tokenLogFile, "Authentication Response", response);

                final String tokenAuthorizationCode = extractParameterValue(response.getHeaders().getFirst("Location"),
                    "code");
                appendTokenToFile(tokenLogFile, "Authorization Code",
                    tokenAuthorizationCode + "\n" + jwtToJson(tokenAuthorizationCode));

                final String ssToken = extractParameterValue(response.getHeaders().getFirst("Location"), "sso_token");
                appendTokenToFile(tokenLogFile, "SSO Token", ssToken + "\n" + jwtToJson(ssToken));
            }
        );

        idpClient.setAfterTokenCallback(response ->
            appendResponseToFile(tokenLogFile, "Token Response", response));

        // Access Token
        final IdpTokenResult tokenResponse = idpClient.login(egkUserIdentity);
        final String accessToken = tokenResponse.getAccessToken().getJwtRawString();
        appendTokenToFile(tokenLogFile, "Access Token", accessToken + "\n" + jwtToJson(accessToken));

        // Id Token
        final String idToken = tokenResponse.getIdToken().getJwtRawString();
        appendTokenToFile(tokenLogFile, "Id Token", idToken + "\n" + jwtToJson(idToken));

        assertThat(tokenLogFile).exists();
    }

    private File createTokenLogFile() throws IOException {
        final File file = new File("target/allTokens.txt");
        if (file.isFile()) {
            file.delete();
        }
        file.createNewFile();
        FileUtils
            .writeStringToFile(file, egkUserIdentity.getCertificate().getSubjectX500Principal().toString() + "\n\n\n",
                StandardCharsets.UTF_8, true);
        return file;
    }

    private void appendRequestToFile(final File file, final String name, final HttpRequest<?> request) {
        final String multipartBody = request.getBody().map(
            body -> body.multiParts().stream()
                .map(part -> part.getName() + "=" + part.getValue())
                .collect(Collectors.joining("\n", "Multiparts:\n", "\n")))
            .orElse("");
        appentToFile(file, name + ":\n" + request.getUrl() + "\n" + multipartBody + "\n");
    }

    private void appendResponseToFile(final File file, final String name, final HttpResponse<?> response) {
        appentToFile(file, name + ":\n" + response.getStatus() + "\n" + response.getHeaders()
            .all().stream()
            .map(header -> header.getName() + "=" + header.getValue())
            .collect(Collectors.joining(",\n")) + "\n" + response.getBody() + "\n");
    }

    private void appendTokenToFile(final File file, final String tokenName, final String tokenContent) {
        appentToFile(file, tokenName + ":\n" + tokenContent + "\n\n");
    }

    private void appentToFile(final File file, final String content) {
        try {
            FileUtils.writeStringToFile(file, content, StandardCharsets.UTF_8, true);
        } catch (final IOException e) {
            throw new RuntimeException(e);
        }
    }
}
