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

package de.gematik.idp.server;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.TestConstants;
import de.gematik.idp.authentication.AuthenticationChallengeBuilder;
import de.gematik.idp.client.BiometrieClient;
import de.gematik.idp.client.IdpClient;
import de.gematik.idp.client.data.DiscoveryDocumentResponse;
import de.gematik.idp.client.data.RegistrationData;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.token.IdpJwe;
import de.gematik.rbellogger.RbelLogger;
import de.gematik.rbellogger.captures.WiremockCapture;
import de.gematik.rbellogger.converter.RbelConfiguration;
import de.gematik.rbellogger.converter.initializers.RbelKeyFolderInitializer;
import de.gematik.rbellogger.data.RbelJweElement;
import de.gematik.rbellogger.data.RbelStringElement;
import de.gematik.rbellogger.key.RbelKey;
import de.gematik.rbellogger.key.RbelKeyManager;
import de.gematik.rbellogger.renderer.RbelHtmlRenderer;
import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.spec.SecretKeySpec;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Slf4j
public class TokenLoggerTest {

    private final static Map<String, String> MASKING_FUNCTIONS = new HashMap<>();
    private final static Map<String, String> JEXL_NOTE_FUNCTIONS = new HashMap<>();
    private final AtomicReference<Integer> wiremockPort = new AtomicReference<>();
    private final String targetFolder = "target/classes/static/";
    private IdpClient idpClient;
    private PkiIdentity egkUserIdentity;
    private PkiIdentity smcbIdentity;
    @LocalServerPort
    private int localServerPort;
    @Autowired
    private AuthenticationChallengeBuilder authenticationChallengeBuilder;
    private RbelLogger rbelLogger;
    private WiremockCapture wiremockCapture;

    {
        JEXL_NOTE_FUNCTIONS.put("type=='RbelJwtSignature'",
            "Signatur, die nach https://tools.ietf.org/html/rfc7515 gebildet wird. Die Signatur erfolgt über ASCII(BASE64URL(UTF8(JWS Protected Header)) || '.' || BASE64URL(JWS Payload)). "
                + "Es gilt zu beachten das alle Tokens im IDP-Flow in CompactSerialization übertragen werden und dementsprechend alle Header-Claims protected sind.");

        JEXL_NOTE_FUNCTIONS.put("key == 'exp'", "Gültigkeit des Tokens");
        JEXL_NOTE_FUNCTIONS.put("key == 'iat'", "Zeitpunkt der Ausstellung des Tokens");
        JEXL_NOTE_FUNCTIONS.put("key == 'nbf'", "Der Token ist erst ab diesem Zeitpunkt gültig");
        JEXL_NOTE_FUNCTIONS.put("key == 'jti'",
            "A unique identifier for the token, which can be used to prevent reuse of the token. Value is a case-sensitive string.");
        JEXL_NOTE_FUNCTIONS.put("key == 'auth_time'", "Timestamp der Authentisierung");
        JEXL_NOTE_FUNCTIONS.put("key == 'snc'", "server-nonce. Wird verwendet um noise hinzuzufügen.");
        JEXL_NOTE_FUNCTIONS.put("key == 'sub'",
            "subject. Base64(sha256(audClaim + idNummerClaim + serverSubjectSalt))");
        JEXL_NOTE_FUNCTIONS.put("key == 'at_hash'",
            "Erste 16 Bytes des Hash des Authentication Tokens Base64(subarray(Sha256(authentication_token), 0, 16))");
        JEXL_NOTE_FUNCTIONS.put("path =$ 'x5c.0'",
            "Enthält das verwendete Signer-Zertifikat als Base64 ASN.1 DER-Encoding. Hier kommt ausnahmsweise NICHT URL-safes Base64-Encoding zum Einsatz!");
        JEXL_NOTE_FUNCTIONS.put("key == 'alg' && content == 'BP256R1'",
            "Wert analog zu https://tools.ietf.org/html/rfc7518#section-3.1. Zeigt an das die Signatur mit ECDSA mit BrainPool256R1 und SHA-256 gebildet wurde.");
        JEXL_NOTE_FUNCTIONS.put("path =$ 'header.kid' || path =$ 'body.kid'",
            "Identifiziert den hier beschriebenen Schlüssel. Beschreibung siehe https://tools.ietf.org/html/rfc7517#section-4.5");
        JEXL_NOTE_FUNCTIONS.put("key == 'crv' && content == 'BP-256'",
            "Identifiziert die Kurve. Hier wird brainpoolP256r1 verwendet. Beschreibung siehe https://tools.ietf.org/html/rfc5639#section-3.4");
        JEXL_NOTE_FUNCTIONS.put("key == 'x'", "X-Koordinate des öffentlichen Punkts des Schlüssels");
        JEXL_NOTE_FUNCTIONS.put("key == 'y'", "Y-Koordinate des öffentlichen Punkts des Schlüssels");
        JEXL_NOTE_FUNCTIONS.put("key == 'use'",
            "Erlaubte Verwendungen des Schlüssels. Siehe https://tools.ietf.org/html/rfc7517#section-4.2");

        JEXL_NOTE_FUNCTIONS.put("key == 'authorization_endpoint'", "URL des Authorization Endpunkts.");
        JEXL_NOTE_FUNCTIONS.put("key == 'sso_endpoint'", "URL des SSO-Authorization Endpunkts.");
        JEXL_NOTE_FUNCTIONS.put("key == 'auth_pair_endpoint'", "URL des Biometrie-Authorization Endpunkts.");
        JEXL_NOTE_FUNCTIONS.put("key == 'token_endpoint'", "URL des Authorization Endpunkts.");
        JEXL_NOTE_FUNCTIONS.put("key == 'uri_pair'", "URL des Pairing-Endpunkts");
        JEXL_NOTE_FUNCTIONS.put("key == 'uri_disc'", "URL des Discovery-Dokuments");
        JEXL_NOTE_FUNCTIONS.put("key == 'puk_uri_auth'", "URL einer JWK-Struktur des Authorization Public-Keys");
        JEXL_NOTE_FUNCTIONS.put("key == 'puk_uri_token'", "URL einer JWK-Struktur des Token Public-Keys");
        JEXL_NOTE_FUNCTIONS
            .put("key == 'jwks_uri'", "URL einer JWKS-Struktur mit allen vom Server verwendeten Schlüsseln");
        JEXL_NOTE_FUNCTIONS.put("key == 'njwt'", "Ein verschachtelt enthaltenes JWT");
        JEXL_NOTE_FUNCTIONS.put("key == 'Date'", "Zeitpunkt der Antwort.");

        JEXL_NOTE_FUNCTIONS.put("key == 'User-Agent'",
            "Der User-Agent des Clients. Muss vorhanden sein. Wird gegen eine Blocklist geprüft");
        JEXL_NOTE_FUNCTIONS.put("key == 'Connection'", "Nicht verpflichtend");
        JEXL_NOTE_FUNCTIONS.put("key == 'Accept-Encoding'", "Nicht verpflichtend");
        JEXL_NOTE_FUNCTIONS.put("key == 'Host'", "Nicht verpflichtend");
        JEXL_NOTE_FUNCTIONS.put("element.originalUrl == '/discoveryDocument' &&"
            + "element.getClass().getSimpleName() == 'RbelPathElement'", "Die konkrete URL kann und wird abweichen!");
        JEXL_NOTE_FUNCTIONS.put("key == 'Version' && message.isResponse",
            "Parameter der Referenz-Implementierung welcher die aktuelle Version zeigt.");

        addRequestResponseNotes("GET", "/discoveryDocument", "Abfrage des Discovery Documents",
            "Das Discovery-Document des IDP");
        JEXL_NOTE_FUNCTIONS
            .put(
                "message.url=^'/.well-known/openid-configuration' && message.method=='GET' && type=='RbelJwtSignature'",
                "Die Signatur des Discovery Documents kann mit dem im Header enthaltenen Zertifikat ('x5c') überprüft werden. Dieses Zertifikat muss natürlich seinerseits per TUC-PKI 018 auf vertrauenswürdigkeit geprüft werden.");
        addRequestResponseNotes("GET", "/idpSig/jwk.json", "Abfrage des puk_idp_sig", "Der puk_idp_sig");
        addRequestResponseNotes("GET", "/idpEnc/jwk.json", "Abfrage des puk_idp_enc", "Der puk_idp_enc. "
            + "Dieser kommt ohne x5c-claim daher. Es handelt sich um einen einfachen Schlüssel und nicht um ein Zertifikat. Der öffentliche Punkt wird mit dem übergebenen x und y Koordinaten beschrieben");
        addRequestResponseNotes("GET", "/sign_response?", "Abfrage der Client Challenge. "
            + "Dies ist die erste Nachricht des eigentlichen Protokoll", "Die zu signierende Challenge "
            + "des Servers.");
        addRequestResponseNotes("POST", "/sign_response",
            "Das Authenticator-Modul überträgt ein \"CHALLENGE_TOKEN\" als Response auf die Challenge an den IdP-Dienst. Das \"CHALLENGE_TOKEN\" wird base64 codiert versendet und beinhaltet die signierte Challenge und das Authentifizierungszertifikat der Smartcard.",
            "Der Authorization-Endpunkt liefert den \"AUTHORIZATION_CODE\" innerhalb einer HTTP-Redirection (HTTP-Status Code 302) an das Primärsystem zurück. Die konkrete URL des \"location\" Attributs der HTTP 302 Response ist nicht relevant.");

        addParameterNotesRequest("GET", "/sign_response?",
            Map.of("scope",
                "Der Scope entspricht dem zwischen E-Rezept-Fachdienst und IDP festgelegten Wert. Mit diesem antwortet der E-Rezept-Fachdienst bei fehlendem ACCESS_TOKEN und http-Statuscode 401.",
                "state",
                "Dieser Parameter wird vom Client zufällig generiert, um CSRF zu verhindern. Indem der Server mit diesem Wert antwortet, werden Redirects legitmiert.",
                "client_id",
                "Die Client-ID des Primärsystems wird beim Registrieren des Primärsystems beim IDP festgelegt.",
                "nonce",
                "String zu Verhinderung von CSRF-Attacken. Dieser Wert ist optional. Wenn er mitgegeben wird muss der gleiche Wert im abschließend ausgegebenen ID-Token wieder auftauchen.",
                "redirect_uri",
                "Die URL wird vom Primärsystem beim Registrierungsprozess im IDP hinterlegt und leitet die Antwort des Servers an diese Adresse um.",
                "response_type",
                "Referenziert den erwarteten Response-Type des Flows. Muss immer 'code' lauten. Damit wird angezeigt das es sich hierbei um einen Authorization Code Flow handelt. Für eine nähere Erläuterung siehe OpenID-Spezifikation.",
                "code_challenge_method",
                "Das Primärsystem generiert einen Code-Verifier und erzeugt darüber einen Hash im Verfahren SHA-256, hier abgekürzt als S256. Teil von PKCE.",
                "code_challenge",
                "Der Hashwert des Code-Verifiers wird zum IDP als Code-Challenge gesendet. Teil von PKCE."));
        addParameterNotesResponse("GET", "/sign_response?",
            Map.of("challenge",
                "Die vom Client mittels der eGK bzw. SMC-B zu signierende Challenge besteht aus einem Base64-codierten Challenge-Token."));
        JEXL_NOTE_FUNCTIONS
            .put(
                "request.url =~ '.*/sign_response.*' && request.method=='GET' && message.isResponse && path == 'body' && type == 'RbelJsonElement'",
                "Dieses JSON beschreibt die zu unterschreibende Challenge.");
        JEXL_NOTE_FUNCTIONS
            .put(
                "request.url =~ '.*/sign_response.*' && message.isResponse && path == 'body.user_consent.requested_scopes'",
                "Enthält die zu authorisierenden Anwendungen.");
        JEXL_NOTE_FUNCTIONS.put(
            "request.url =~ '.*/sign_response.*' && message.isResponse && path == 'body.user_consent.requested_scopes.e-rezept'",
            "Zeigt an das ein Zugang zum E-Rezept-FD gewünscht wird.");
        JEXL_NOTE_FUNCTIONS.put(
            "request.url =~ '.*/sign_response.*' && message.isResponse && path == 'body.user_consent.requested_scopes.openid'",
            "Ist immer notwendig.");
        JEXL_NOTE_FUNCTIONS.put(
            "request.url =~ '.*/sign_response.*' && message.isResponse && path == 'body.user_consent.requested_claims'",
            "Listet die freizugebenden Daten auf. Für das E-Rezept sind das Attribute aus dem Zertifikat.");
        JEXL_NOTE_FUNCTIONS.put(
            "request.url =~ '.*/sign_response.*' && message.isResponse && path == 'body.user_consent'",
            "Alle aufgeführten Daten sollen dem Benutzer selbst angezeigt werden (Formatierung und Formulierung stehen "
                + "hierbei dem Authentisierungsmodul frei) um diesem die Möglichkeit zu geben eine informierte "
                + "Entscheidung zu treffen ob der Client tatsächlich den beschriebenen Zugang erhalten soll.");
        JEXL_NOTE_FUNCTIONS.put(
            "request.url =~ '.*/sign_response.*' && message.isResponse && path == 'body.challenge'",
            "Dies ist die Challenge des Servers die es zu signieren gilt.");

        JEXL_NOTE_FUNCTIONS.put("message.url=^'/sign_response' && message.method=='POST' "
                + "&& path=='body.signed_challenge.body.njwt'",
            "Diese JWT muss vom Client erstellt werden. Es wird mit der Karte signiert welche authentifiziert werden soll. Das zugehörige Zertifikat (C.CH.AUT) wird im x5c-Header des Tokens übertragen");
        JEXL_NOTE_FUNCTIONS.put("message.url=^'/sign_response' && message.method=='POST' "
                + "&& path=='body.signed_challenge.body.njwt.body.njwt'",
            "Dieses Token ist die vom Server in der vorigen Nachricht übergebene Challenge. Sie muss exakt wie empfangen auch wieder übertragen werden.");
        JEXL_NOTE_FUNCTIONS.put("message.url=^'/sign_response' && message.method=='POST' "
                + "&& path=='body.signed_challenge.header'",
            "Das 'exp' in diesem Header muss dem 'exp' aus der server-Challenge (also njwt->njwt->exp) entsprechen. 'epk' muss übergeben werden und beschreibt den benutzen Schlüssel zum chiffrieren.");
        addParameterNotesRequest("POST", "/sign_response",
            Map.of("signed_challenge",
                "Hierbei handelt es sich um das signierte und verschlüsselte \"CHALLENGE_TOKEN\"."));
        addParameterNotesResponse("POST", "/sign_response",
            Map.of("code",
                "Der Authorization-Code. Er berechtigt zur Abholung eines Access-Tokens. Er ist vom IDP für den IDP verschlüsselt und dementsprechend vom Client nicht weiter zu verarbeiten.",
                "ssotoken",
                "Der SSO-Token. Mit diesem kann der Client sich wiederholt einloggen ohne erneut den Besitz der Karte durch unterschreiben einer Challenge beweisen zu müssen. Er ist vom IDP für den IDP verschlüsselt und dementsprechend vom Client nicht weiter zu verarbeiten.",
                "state",
                "Der state der Session. Sollte dem zufällig generierten state-Wert aus der initialen Anfrage entsprechen."));

        addRequestResponseNotes("POST", "/token",
            "Die Abfrage des Access-Tokens durch den Client selbst",
            "Rückgabe des Access- und ID-Tokens");
        addParameterNotesRequest("POST", "/token",
            Map.of("key_verifier",
                "JWE, welches den code_verifier sowie den token_key enthält. Dies ist ein AES-Schlüssel welcher vom Server zur Verschlüsselung der Token-Rückgaben verwendet wird.",
                "code",
                "Der Authorization-Code, so wie er vom Server in der vorigen Antwort auf POST /sign_response zurück gegeben wurde",
                "grant_type",
                "Muss exakt diesen Wert enthalten, da es sich um eine Implementierung des OIDC Authorization Code Flows handelt.",
                "redirect_uri",
                "Die für den Client beim Server hinterlegte redirect_uri. Muss dem bei der Registrierung hinterlegten Wert entsprechen.",
                "client_id",
                "Die client_id des Clients. Wird bei der Registrierung vergeben."));
        JEXL_NOTE_FUNCTIONS.put("path=='body.key_verifier.header'",
            "Dieser Token wird für den Server mit dem puk_idp_enc verschlüsselt.");
        JEXL_NOTE_FUNCTIONS.put("path=='body.key_verifier.body'",
            "Enthalten ist der code_verifier (der zu dem code_challenge-Wert aus der initialen Anfrage passen muss) sowie der token_key. Dies ist ein vom Client zufällig gewürfelter AES256-Schlüssel in Base64-URL-Encoding. "
                + "Der Server benutzt diesen Schlüssel zur Chiffrierung der beiden Token-Rückgaben in der Response (ID- und Access-Token).");

        JEXL_NOTE_FUNCTIONS.put("path=='body.access_token'",
            "Das verschlüsselte Access-Token. Der Server chiffriert das Token selbst zur Sicherung des Transport-Weges. Zur Verschlüsselung verwendet wird hier der token_key aus der Anfrage des Clients.");
        JEXL_NOTE_FUNCTIONS.put("path=='body.access_token.body.njwt'",
            "Das eigentliche Access-Token, so wie es zur Vorlage beim Fachdienst verwendet werden soll.");
        JEXL_NOTE_FUNCTIONS.put("path=='body.id_token'",
            "Das verschlüsselte ID-Token. Der Server chiffriert das Token selbst zur Sicherung des Transport-Weges. Zur Verschlüsselung verwendet wird hier der token_key aus der Anfrage des Clients.");
        JEXL_NOTE_FUNCTIONS.put("path=='body.id_token.body.njwt'",
            "Das eigentliche ID-Token. Enthält Informationen zum Identifizieren des Versicherten");

        JEXL_NOTE_FUNCTIONS
            .put(
                "element.class.simpleName=='RbelJweEncryptionInfo' && element.decryptedUsingKeyWithId == 'IDP symmetricEncryptionKey'",
                "Der Algorithmus und der Schlüssel sind nicht nicht fest, genügen aber dem erforderlichen Sicherheitsniveau der gematik. "
                    + "Der Client hat keine Möglichkeit den Inhalt dieses Tokens zu lesen. Ausnahme ist der Header, und damit der 'exp'-Claim welcher die Gültigkeit des JWE anzeigt.");
        JEXL_NOTE_FUNCTIONS
            .put(
                "element.class.simpleName=='RbelJweEncryptionInfo' && element.decryptedUsingKeyWithId == 'prk_idp_enc'",
                "Muss mit dem puk_idp_enc verschlüsselt werden. Näheres ist https://tools.ietf.org/html/rfc7516 zu entnehmen.");
        JEXL_NOTE_FUNCTIONS
            .put("element.class.simpleName=='RbelJweEncryptionInfo' && element.decryptedUsingKeyWithId == 'token_key'",
                "Wird vom Server mit dem token_key verschlüsselt der in der korrespondierenden Anfrage übertragen wurde.");
    }

    private void addParameterNotesRequest(final String httpVerb, final String url,
        final Map<String, String> parameterNotes) {
        for (final Entry<String, String> entry : parameterNotes.entrySet()) {
            JEXL_NOTE_FUNCTIONS.put("key == '" + entry.getKey() + "'", entry.getValue());
        }
    }

    private void addParameterNotesResponse(final String httpVerb, final String url,
        final Map<String, String> parameterNotes) {
        for (final Entry<String, String> entry : parameterNotes.entrySet()) {
            JEXL_NOTE_FUNCTIONS.put(//"request.url =^ '" + url + "' "
                //+ "&& request.method=='" + httpVerb + "' && message.isResponse "
                "key == '" + entry.getKey() + "'", entry.getValue());
        }
    }

    private void addRequestResponseNotes(final String verb, final String url, final String requestNote,
        final String responseNote) {
        JEXL_NOTE_FUNCTIONS.put("message.url =^ '" + url + "' "
            + "&& message.method=='" + verb + "' && type == 'RbelHttpRequest'", requestNote);
        JEXL_NOTE_FUNCTIONS.put("request.url =^ '" + url + "' && request.method=='" + verb + "' "
            + "&& type == 'RbelHttpResponse'", responseNote);
    }


    @BeforeEach
    public void startup(
        @PkiKeyResolver.Filename("80276883110000018680-C_CH_AUT_E256.p12") final PkiIdentity clientIdentity,
        @PkiKeyResolver.Filename("80276883110000129084-C_HP_AUT_E256.p12") final PkiIdentity smcbIdentity) {
        rbelLogger = RbelLogger.build(
            new RbelConfiguration()
                .addKey("IDP symmetricEncryptionKey",
                    new SecretKeySpec(DigestUtils.sha256("geheimerSchluesselDerNochGehashtWird"), "AES"),
                    RbelKey.PRECEDENCE_KEY_FOLDER)
                .addInitializer(new RbelKeyFolderInitializer("src/main/resources"))
                .addPostConversionListener(RbelJweElement.class, RbelKeyManager.RBEL_IDP_TOKEN_KEY_LISTENER)
                .addPreConversionMapper(RbelStringElement.class, (path, context) -> {
                    if (path.getContent().contains("localhost:" + wiremockPort.get())) {
                        return new RbelStringElement(
                            path.getContent().replace("localhost:" + wiremockPort.get(), "url.des.idp"));
                    } else if (path.getContent().contains("localhost:" + localServerPort)) {
                        return new RbelStringElement(
                            path.getContent().replace("localhost:" + localServerPort, "url.des.idp"));
                    } else {
                        return path;
                    }
                })
        );

        JEXL_NOTE_FUNCTIONS.forEach((k, v) -> rbelLogger.getValueShader().addJexlNoteCriterion(k, v));
        MASKING_FUNCTIONS.forEach((k, v) -> rbelLogger.getValueShader().addSimpleShadingCriterion(k, v));
        rbelLogger.getValueShader().addJexlShadingCriterion("path =^ 'header.Location' && key == 'code'",
            "<Authorization Code in Base64-URL-Safe Encoding. Wird unten detaillierter aufgeführt>");
        rbelLogger.getValueShader().addJexlShadingCriterion("path =^ 'header.Location' && key == 'ssotoken'",
            "<SSO-Token in Base64-URL-Safe Encoding. Wird unten detaillierter aufgeführt>");

        egkUserIdentity = clientIdentity;
        this.smcbIdentity = smcbIdentity;
    }

    private void initializeWiremockCapture() throws MalformedURLException {
        rbelLogger.getMessageHistory().clear();

        wiremockCapture = WiremockCapture.builder()
            .rbelConverter(rbelLogger.getRbelConverter())
            .proxyFor("http://localhost:" + localServerPort)
            .build()
            .initialize();
        wiremockPort.set(new URL(wiremockCapture.getProxyAdress()).getPort());

//        doReturn(wiremockCapture.getProxyAdress())
//            .when(serverUrlService).determineServerUrl(any());
//        doReturn(wiremockCapture.getProxyAdress())
//            .when(serverUrlService).determineServerUrl();
        ReflectionTestUtils.setField(authenticationChallengeBuilder, "uriIdpServer", wiremockCapture.getProxyAdress());

        log.info("wiremock url: " + wiremockCapture.getProxyAdress());
        log.info("proxy for: " + wiremockCapture.getProxyFor());
        log.info("spring url: http://localhost:" + localServerPort);

        idpClient = IdpClient.builder()
            .clientId(TestConstants.CLIENT_ID_E_REZEPT_APP)
            .discoveryDocumentUrl(wiremockCapture.getProxyAdress() + IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT)
            .redirectUrl(TestConstants.REDIRECT_URI_E_REZEPT_APP)
            .build();
    }

    @Test
    public void writeAllTokensToFile() throws IOException {
        performAndWriteFlow(() -> {
            idpClient.initialize();
            patchIdpUrls(idpClient);

            idpClient.login(egkUserIdentity);
        }, targetFolder + "tokenFlowEgk.html", "EGK-Login beim IdP");

        performAndWriteFlow(() -> {
            idpClient.initialize();
            patchIdpUrls(idpClient);

            final IdpJwe ssoToken = idpClient.login(egkUserIdentity).getSsoToken();

            idpClient.loginWithSsoToken(ssoToken);
        }, targetFolder + "tokenFlowSso.html", "EGK-Login beim IdP mit anschließendem SSO-Token-Login");

        performAndWriteFlow(() -> {
            final IdpClient psIdpClient = IdpClient.builder()
                .clientId(TestConstants.CLIENT_ID_GEAMTIK_TEST_PS)
                .discoveryDocumentUrl(wiremockCapture.getProxyAdress() + IdpConstants.DISCOVERY_DOCUMENT_ENDPOINT)
                .redirectUrl(TestConstants.REDIRECT_URI_GEAMTIK_TEST_PS)
                .build();
            psIdpClient.initialize();
            patchIdpUrls(psIdpClient);
            psIdpClient.login(smcbIdentity);
        }, targetFolder + "tokenFlowPs.html", "Primärsystem-Login beim IdP ohne SSO-Token");

        performAndWriteFlow(() -> {
            idpClient.initialize();
            patchIdpUrls(idpClient);
            idpClient.setScopes(Set.of(IdpScope.PAIRING, IdpScope.OPENID));

            final BiometrieClient biometrieClient = BiometrieClient.builder()
                .discoveryDocumentResponse(idpClient.getDiscoveryDocumentResponse())
                .accessToken(idpClient.login(egkUserIdentity).getAccessToken())
                .build();

            final RegistrationData registrationData = biometrieClient.insertPairing(egkUserIdentity, new KeyPair(
                smcbIdentity.getCertificate().getPublicKey(),
                smcbIdentity.getPrivateKey()));

            biometrieClient.getAllPairings();

            idpClient.loginWithAltAuth(registrationData, smcbIdentity.getPrivateKey());
        }, targetFolder + "biometrie.html", "Registrierung eines neuen Geräts beim Server");
    }

    private void patchIdpUrls(IdpClient idpClient) {
        final DiscoveryDocumentResponse ddResponse = idpClient.getDiscoveryDocumentResponse();
        ddResponse.setAuthorizationEndpoint(ddResponse.getAuthorizationEndpoint()
            .replace(wiremockCapture.getProxyFor(), wiremockCapture.getProxyAdress()));
        ddResponse.setAuthPairEndpoint(ddResponse.getAuthPairEndpoint()
            .replace(wiremockCapture.getProxyFor(), wiremockCapture.getProxyAdress()));
        ddResponse.setPairingEndpoint(ddResponse.getPairingEndpoint()
            .replace(wiremockCapture.getProxyFor(), wiremockCapture.getProxyAdress()));
        ddResponse.setSsoEndpoint(ddResponse.getSsoEndpoint()
            .replace(wiremockCapture.getProxyFor(), wiremockCapture.getProxyAdress()));
        ddResponse.setTokenEndpoint(ddResponse.getTokenEndpoint()
            .replace(wiremockCapture.getProxyFor(), wiremockCapture.getProxyAdress()));
    }

    private void performAndWriteFlow(final Runnable performer, final String filename, final String title)
        throws IOException {
        try {
            initializeWiremockCapture();

            performer.run();
        } finally {
            try {
                wiremockCapture.close();
            } catch (final Exception e) {
                e.printStackTrace();
            }

            log.info("Starting Flow Rendering...");
            final RbelHtmlRenderer rbelHtmlRenderer = new RbelHtmlRenderer(rbelLogger.getValueShader());
            rbelHtmlRenderer.setTitle(title);
            rbelHtmlRenderer.setSubTitle("Gerendert mit https://github.com/gematik/app-RbelLogger");
            FileUtils.writeStringToFile(new File(filename),
                rbelHtmlRenderer.doRender(rbelLogger.getMessageHistory()),
                Charset.defaultCharset());
            log.info("Completed Flow Rendering!");
        }
    }
}
