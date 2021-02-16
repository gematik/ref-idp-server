package de.gematik.idp.test.steps;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import de.gematik.idp.test.steps.model.*;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Step;
import org.apache.commons.codec.binary.Base64;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;

@Slf4j
public class IdpBiometricsSteps extends IdpStepsBase {

    @Step
    @SneakyThrows
    public void signPairingData(final String keyfile) {
        final Map<ContextKey, Object> ctxt = Context.getThreadContext();
        final Key pkey = readPrivateKeyFrom(keyfile);
        final Certificate cert = readCertFrom(keyfile);
        final Map<String, String> pairingData = (Map<String, String>) ctxt.get(ContextKey.PAIRING_DATA);
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

    @SneakyThrows
    public void registerDeviceWithCert(final String certFile) {
        final Certificate cert = readCertFrom(certFile);

        final Map<String, String> ctxtDevInfo = (Map<String, String>) Context.getThreadContext()
            .get(ContextKey.DEVICE_INFO);
        final Map<String, String> devTypeInfo = ctxtDevInfo.entrySet().stream()
            .filter(entry -> !entry.getKey().equals("device_name")).
                collect(Collectors
                    .toMap(Map.Entry::getKey, entry -> String.valueOf(entry.getValue())));
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
    public void deregisterDeviceWithKey(final String keyVerifier) {
        final Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + Context.getThreadContext().get(ContextKey.ACCESS_TOKEN));
        headers.put("User-Agent", "TODO some UA, probably configurable");

        Context.getThreadContext().put(ContextKey.RESPONSE, requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getPairingEndpoint() + "/" + keyVerifier, headers,
            HttpMethods.DELETE, null, null, HttpStatus.NOCHECK));
    }

    public void requestAllPairings() {
        final Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer " + Context.getThreadContext().get(ContextKey.ACCESS_TOKEN));
        headers.put("User-Agent", "TODO some UA, probably configurable");

        Context.getThreadContext().put(ContextKey.RESPONSE, requestResponseAndAssertStatus(
            Context.getDiscoveryDocument().getPairingEndpoint(), headers,
            HttpMethods.GET, null, null, HttpStatus.NOCHECK));

    }

    @SneakyThrows
    public String composeRawString(final Map<String, String> bodyClaims, final Key signerKey) {
        final JwtClaims claims = new JwtClaims();
        bodyClaims.forEach(claims::setClaim);

        final JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        if (signerKey != null) {
            jws.setKey(signerKey);
            if (signerKey instanceof ECPrivateKey) {
                jws.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
            } else if (signerKey instanceof RSAPrivateKey) {
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_PSS_USING_SHA256);
            } else {
                Assertions.fail("Could not identify Signer-Key: " + signerKey.getClass().toString());
            }
        } else {
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);
            jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
        }

        /* TODO for (final String key : headerClaims.keySet()) {
            jws.setHeader(key, headerClaims.get(key));
        }
        */

        /*if (includeSignerCertificateInHeader) {
            if (certificate == null) {
                throw new IdpJoseException("Could not include x5c-header: certificate not set");
            }
            jws.setCertificateChainHeaderValue(certificate);
        }
         */
        return jws.getCompactSerialization();
    }
}
