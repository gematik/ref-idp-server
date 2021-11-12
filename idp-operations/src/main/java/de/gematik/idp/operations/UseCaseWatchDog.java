package de.gematik.idp.operations;

import de.gematik.idp.test.steps.*;
import de.gematik.idp.test.steps.helpers.CucumberValuesConverter;
import de.gematik.idp.test.steps.helpers.IdpTestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.AccessTokenType;
import de.gematik.idp.test.steps.model.CodeAuthType;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import de.gematik.test.bdd.TestEnvironmentConfigurator;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.RandomStringUtils;

@Slf4j
public class UseCaseWatchDog {

    public static void main(final String[] args) {
        if (args.length != 1) {
            log.error("We expect exactly ONE argument being one of [discdoc|signedchallenge|ssotoken|altauth]!");
            System.exit(128);
        }
        if (TestEnvironmentConfigurator.getProperty("IDP_SERVER") == null) {
            log.error("IDP_SERVER must be set as java system property or system env var!");
            System.exit(128);
        }
        try {
            Map<String, String> data = new HashMap<>(
                Map.of("scope", AccessTokenType.EREZEPT.toScope() + " openid"));
            final String certFile = "/certs/valid/80276883110000018680-C_CH_AUT_E256.p12";
            final String accessTokenType = AccessTokenType.EREZEPT.toString();
            switch (args[0]) {
                case "discdoc":
                    disc.iRequestTheInternalDiscoveryDocument(HttpStatus.SUCCESS);
                    // TODO save discdoc for reuse by other use cases to file system
                    return;
                case "signedchallenge":
                    disc.initializeFromDiscoveryDocument();
                    Context.getDiscoveryDocument().readPublicKeysFromURIs();
                    requestAnAccessTokenWitheGK(accessTokenType, CodeAuthType.SIGNED_CHALLENGE,
                        certFile, "00", data);
                    return;
                case "ssotoken":
                    disc.initializeFromDiscoveryDocument();
                    Context.getDiscoveryDocument().readPublicKeysFromURIs();
                    requestAnAccessTokenWitheGK(accessTokenType, CodeAuthType.SIGNED_CHALLENGE,
                        cucumberValuesConverter.parseDocString(certFile), "00", data);
                    data = new HashMap<>(
                        Map.of("scope", AccessTokenType.EREZEPT.toScope() + " openid"));
                    requestAnAccessTokenWitheGK(accessTokenType, CodeAuthType.SSO_TOKEN,
                        cucumberValuesConverter.parseDocString(certFile), "00", data);
                    return;
                case "altauth":
                    data.put("scope", "pairing openid");
                    performAltAuthUseCase(data, certFile);

                    break;
                default:
                    log.error("Unknown use case '" + args[0] + "'");
                    System.exit(128);
            }
        } catch (final Throwable t) {
            log.error("Exception while executing use case '" + args[0] + "'", t);
            System.exit(127);
        }
    }

    private static void performAltAuthUseCase(final Map<String, String> data, final String certFile)
        throws URISyntaxException {
        final String keyid = "key_" + System.currentTimeMillis();
        try {
            disc.initializeFromDiscoveryDocument();
            Context.getDiscoveryDocument().readPublicKeysFromURIs();
            requestAnAccessTokenWitheGK(AccessTokenType.PAIRING.toString(), CodeAuthType.SIGNED_CHALLENGE,
                certFile, "00", data);

            final Map<String, String> mapDevInfo = new HashMap<>(Map.of(
                "name", "eRezeptApp",
                "manufacturer", "Fair Phone",
                "product", "FairPhone 3",
                "model", "F3",
                "os", "Android"));
            mapDevInfo.put("os_version", "1.0.2 f");
            Context.get().put(ContextKey.DEVICE_INFO, mapDevInfo);

            final Map<String, String> mapPairData = new HashMap<>(Map.of(
                "se_subject_public_key_info", "/keys/valid/Pub_Se_Aut-1.pem",
                "key_identifier", keyid,
                "product", "FairPhone 3",
                "serialnumber", "$FILL_FROM_CERT",
                "issuer", "$FILL_FROM_CERT"));
            mapPairData.put("not_after", "$FILL_FROM_CERT");
            mapPairData
                .put("auth_cert_subject_public_key_info", certFile);
            Context.get().put(ContextKey.PAIRING_DATA, mapPairData);

            biosteps.signPairingData(certFile);
            biosteps.registerDeviceWithCert(certFile, "1.0");
            biosteps.assertResponseStatusIs(HttpStatus.SUCCESS);

            auth.setCodeVerifier(
                "drfxigjvseyirdjfg03q489rtjoiesrdjgfv3ws4e8rujgf0q3gjwe4809rdjt89fq3j48r9jw3894efrj");
            final Map<String, String> mapChallenge = new HashMap<>(Map.of(
                "client_id", IdpTestEnvironmentConfigurator.getTestEnvVar("client_id"),
                "scope", "openid pairing",
                "code_challenge", "Ca3Ve8jSsBQOBFVqQvLs1E-dGV1BXg2FTvrd-Tg19Vg",
                "code_challenge_method", "S256",
                "redirect_uri", IdpTestEnvironmentConfigurator.getTestEnvVar("redirect_uri"),
                "state", "operationsTest",
                "nonce", "123456",
                "response_type", "code"));
            auth.getChallenge(mapChallenge, HttpStatus.SUCCESS);

            mapDevInfo.clear();
            mapDevInfo.putAll(Map.of(
                "name", "eRezeptApp",
                "manufacturer", "Fair Phone",
                "product", "FairPhone 3",
                "model", "F3",
                "os", "Android"));
            mapDevInfo.put("os_version", "1.0.2 f");
            Context.get().put(ContextKey.DEVICE_INFO, mapDevInfo);

            final Map<String, String> mapAuthData = Map.of(
                "authentication_data_version", "1.0",
                "auth_cert", certFile,
                "key_identifier", keyid,
                "amr", "[\"mfa\", \"hwk\", \"face\"]");
            biosteps.createAuthenticationData(mapAuthData);

            biosteps.signAuthenticationData("/keys/valid/Priv_Se_Aut-1-pkcs8.der", "1.0");

            author.getCode(CodeAuthType.ALTERNATIVE_AUTHENTICATION, HttpStatus.SUCCESS);
            Context.get()
                .putString(ContextKey.REDIRECT_URI, IdpTestEnvironmentConfigurator.getTestEnvVar("redirect_uri"));
            access.getToken(HttpStatus.SUCCESS, null);
        } finally {
            log.info("CLEANING UP!");
            final Map<String, String> mapUnregister = new HashMap<>(Map.of(
                "client_id", IdpTestEnvironmentConfigurator.getTestEnvVar("client_id"),
                "scope", "pairing openid",
                "code_challenge_method", "S256",
                "redirect_uri", IdpTestEnvironmentConfigurator.getTestEnvVar("redirect_uri"),
                "state", "operationsTest",
                "nonce", "123456",
                "response_type", "code"));

            requestAnAccessTokenWitheGK(AccessTokenType.PAIRING.toString(), CodeAuthType.SIGNED_CHALLENGE,
                certFile, "00", mapUnregister);
            biosteps.deregisterDeviceWithKey(keyid);
            biosteps.assertResponseStatusIs(HttpStatus.SUCCESS);
        }
    }

    static IdpDiscoveryDocumentSteps disc = new IdpDiscoveryDocumentSteps();

    static IdpAuthenticationSteps auth = new IdpAuthenticationSteps();

    static IdpAuthorizationSteps author = new IdpAuthorizationSteps();

    static IdpAccessTokenSteps access = new IdpAccessTokenSteps();

    static IdpBiometricsSteps biosteps = new IdpBiometricsSteps();

    static CucumberValuesConverter cucumberValuesConverter = new CucumberValuesConverter();

    @SneakyThrows
    static void requestAnAccessTokenWitheGK(final String accessType, final CodeAuthType authType,
        final String certFile, final String password, final Map<String, String> data) {
        final String codeVerifier = data.getOrDefault("codeVerifier", RandomStringUtils.random(60, true, true));
        data.remove("codeVerifier");
        auth.setCodeVerifier(codeVerifier);

        data.putIfAbsent("client_id", IdpTestEnvironmentConfigurator.getTestEnvVar("client_id"));
        data.putIfAbsent("scope", AccessTokenType.fromString(accessType).toScope() + " openid");
        data.putIfAbsent("code_challenge", auth.generateCodeChallenge(codeVerifier));
        data.putIfAbsent("code_challenge_method", "S256");
        data.putIfAbsent("redirect_uri", IdpTestEnvironmentConfigurator.getTestEnvVar("redirect_uri"));
        data.putIfAbsent("state", RandomStringUtils.random(16, true, true));
        data.putIfAbsent("nonce", RandomStringUtils.random(20, true, true));
        data.putIfAbsent("response_type", "code");

        auth.getChallenge(data, HttpStatus.SUCCESS);
        author.signChallenge(cucumberValuesConverter.parseDocString(certFile), password);
        author.getCode(authType, HttpStatus.SUCCESS);
        Context.get().put(ContextKey.REDIRECT_URI, data.get("redirect_uri"));
        access.getToken(HttpStatus.SUCCESS, null);
    }
}
