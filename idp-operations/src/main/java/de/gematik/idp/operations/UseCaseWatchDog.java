package de.gematik.idp.operations;

import de.gematik.idp.test.steps.IdpAccessTokenSteps;
import de.gematik.idp.test.steps.IdpAuthenticationSteps;
import de.gematik.idp.test.steps.IdpAuthorizationSteps;
import de.gematik.idp.test.steps.IdpDiscoveryDocumentSteps;
import de.gematik.idp.test.steps.helpers.CucumberValuesConverter;
import de.gematik.idp.test.steps.helpers.IdpTestEnvironmentConfigurator;
import de.gematik.idp.test.steps.model.AccessTokenType;
import de.gematik.idp.test.steps.model.CodeAuthType;
import de.gematik.idp.test.steps.model.HttpStatus;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import de.gematik.test.bdd.TestEnvironmentConfigurator;
import java.util.HashMap;
import java.util.Map;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Steps;
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
                default:
                    log.error("Unknown use case '" + args[0] + "'");
                    System.exit(128);
            }
        } catch (final Throwable t) {
            log.error("Exception while executing use case '" + args[0] + "'", t);
            System.exit(127);
        }
    }

    @Steps
    static IdpDiscoveryDocumentSteps disc = new IdpDiscoveryDocumentSteps();

    @Steps
    static IdpAuthenticationSteps auth = new IdpAuthenticationSteps();

    @Steps
    static IdpAuthorizationSteps author = new IdpAuthorizationSteps();

    @Steps
    static IdpAccessTokenSteps access = new IdpAccessTokenSteps();

    @Steps
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
