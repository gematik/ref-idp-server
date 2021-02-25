package de.gematik.idp.test.steps;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import de.gematik.idp.test.steps.model.*;
import io.restassured.response.Response;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Step;
import org.apache.commons.codec.binary.Base64;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.json.JSONObject;

@Slf4j
public class IdpBiometricsSteps extends IdpStepsBase {

    @Step
    @SneakyThrows
    public void signPairingData(final String keyfile) {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        final Key pkey = readPrivateKeyFrom(keyfile);
        final Certificate cert = readCertFrom(keyfile);
        final Map<String, String> pairingData = (Map<String, String>) ctxt.get(ContextKey.PAIRING_DATA);
        if (pairingData.get("public_key") != null) {
            final PublicKey pubKey = readCertFrom(pairingData.get("public_key")).getPublicKey();
            pairingData.put("public_key", new String(Base64.encodeBase64(pubKey.getEncoded())));
        }
        if (pairingData.get("key_data") != null) {
            final PublicKey pubKeyKeyData = readPublicKeyFromPEM(pairingData.get("key_data"));
            pairingData.put("key_data", new String(Base64.encodeBase64(pubKeyKeyData.getEncoded())));
        }
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(new JSONObject(pairingData).toString());
        jsonWebSignature.setKey(pkey);
        if (cert.getPublicKey().getAlgorithm().equals("EC")) {
            jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
        } else {
            jsonWebSignature.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_PSS_USING_SHA256);
        }
        jsonWebSignature.setHeader("typ", "JWT");
        ctxt.put(ContextKey.SIGNED_PAIRING_DATA, jsonWebSignature.getCompactSerialization());
    }

    @Step
    @SneakyThrows
    public void signAuthenticationData(final String keyfile) {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        final Key pkey = readPrivatKeyFromPkcs8(keyfile);
        final Map<String, String> authenticationData = (Map<String, String>) ctxt.get(ContextKey.AUTHENTICATION_DATA);
        authenticationData.put("challenge_token", (String) ctxt.get(ContextKey.CHALLENGE));

        final Map<String, String> ctxtDevInfo = (Map<String, String>) Context.getThreadContext()
            .get(ContextKey.DEVICE_INFO);
        final Map<String, String> devTypeInfo = new HashMap<>(ctxtDevInfo);
        devTypeInfo.remove("device_name");
        final JSONObject devInfo = new JSONObject();
        devInfo.put("device_name", ctxtDevInfo.get("device_name"));
        devInfo.put("device_type", new JSONObject(devTypeInfo));
        authenticationData.put("device_information", devInfo.toString());
        final String certFile = authenticationData.get("authentication_cert");
        final Certificate cert = readCertFrom(certFile);
        authenticationData.put("authentication_cert", new String(Base64.encodeBase64(cert.getEncoded())));
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setPayload(new JSONObject(authenticationData).toString());
        jsonWebSignature.setKey(pkey);
        jsonWebSignature.setAlgorithmHeaderValue("ES256");
        jsonWebSignature.setHeader("typ", "JWT");
        ctxt.put(ContextKey.SIGEND_AUTHENTICATION_DATA, jsonWebSignature.getCompactSerialization());
    }

    @SneakyThrows
    public void registerDeviceWithCert(final String certFile) {
        final Certificate cert = readCertFrom(certFile);

        final Map<String, String> ctxtDevInfo = (Map<String, String>) Context.getThreadContext()
            .get(ContextKey.DEVICE_INFO);
        final Map<String, String> devTypeInfo = new HashMap<>(ctxtDevInfo);
        devTypeInfo.remove("device_name");
        final JSONObject devInfo = new JSONObject();
        devInfo.put("device_name", ctxtDevInfo.get("device_name"));
        devInfo.put("device_type", new JSONObject(devTypeInfo));

        final JSONObject regData = new JSONObject();
        regData.put("signed_pairing_data", Context.getThreadContext().get(ContextKey.SIGNED_PAIRING_DATA));
        regData.put("authentication_cert", new String(Base64.encodeBase64(cert.getEncoded())));
        regData.put("device_information", devInfo);

        final Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + Context.getThreadContext().get(ContextKey.ACCESS_TOKEN));
        headers.put("User-Agent", "TODO some UA, probably configurable");

        final PublicKey pukEnc = DiscoveryDocument.getPublicKeyFromCertFromJWK(ContextKey.PUK_ENC);
        Context.getThreadContext().put(ContextKey.RESPONSE,
            requestResponseAndAssertStatus(Context.getDiscoveryDocument().getPairingEndpoint(), headers,
                HttpMethods.PUT, null, encrypt(regData.toString(), pukEnc), HttpStatus.NOCHECK));
    }

    @SneakyThrows
    public void deregisterDeviceWithKey(String keyVerifier) {
        final Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + Context.getThreadContext().get(ContextKey.ACCESS_TOKEN));
        headers.put("User-Agent", "TODO some UA, probably configurable");

        if (keyVerifier.equals("$NULL")) {
            keyVerifier = null;
        } else if (keyVerifier.equals("$REMOVE")) {
            keyVerifier = "";
        }
        final Response r = requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getPairingEndpoint() + "/" + keyVerifier, headers,
            HttpMethods.DELETE, null, null, HttpStatus.NOCHECK);
        Context.getThreadContext().put(ContextKey.RESPONSE, r);
    }

    public void requestAllPairings() {
        final Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + Context.getThreadContext().get(ContextKey.ACCESS_TOKEN));
        headers.put("User-Agent", "TODO some UA, probably configurable");

        Context.getThreadContext().put(ContextKey.RESPONSE, requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getPairingEndpoint(), headers,
            HttpMethods.GET, null, null, HttpStatus.NOCHECK));

    }
}
