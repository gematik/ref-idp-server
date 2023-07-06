/*
 *  Copyright 2023 gematik GmbH
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
 */

package de.gematik.idp.server.services;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.token.IdpJwe.createWithPayloadAndExpiryAndEncryptWithKey;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;
import static org.jose4j.jws.EcdsaUsingShaAlgorithm.convertDerToConcatenated;

import de.gematik.idp.authentication.AuthenticationChallengeBuilder;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.EcSignerUtility;
import de.gematik.idp.crypto.RsaSignerUtility;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.ScopeConfiguration;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.data.UserConsentDescriptionTexts;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.tests.PkiKeyResolver;
import de.gematik.idp.tests.PkiKeyResolver.Filename;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.UnaryOperator;
import lombok.SneakyThrows;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ExtendWith(PkiKeyResolver.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SignedChallengeValidationTest {

  private static final String SERVER_KEY_IDENTITY = "serverKeyIdentity";

  @Autowired private IdpAuthenticator idpAuthenticator;
  @Autowired private IdpKey idpEnc;
  @Autowired private IdpKey idpSig;

  private PkiIdentity egkIdentity;

  private JsonWebToken challengeToken;

  @BeforeEach
  public void init(
      final PkiIdentity ecc,
      @Filename("109500969_X114428530_c.ch.aut-ecc") final PkiIdentity egkIdentity) {
    idpSig.setKeyId(Optional.of(SERVER_KEY_IDENTITY));
    this.egkIdentity =
        PkiIdentity.builder()
            .certificate(egkIdentity.getCertificate())
            .privateKey(egkIdentity.getPrivateKey())
            .build();
    final ScopeConfiguration openidConfig =
        ScopeConfiguration.builder().description("openid desc").build();
    final ScopeConfiguration pairingConfig =
        ScopeConfiguration.builder()
            .audienceUrl("erplala")
            .description("erp desc")
            .claimsToBeIncluded(List.of(GIVEN_NAME, FAMILY_NAME))
            .build();

    final AuthenticationChallengeBuilder authenticationChallengeBuilder =
        AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(idpSig.getIdentity()))
            .userConsentConfiguration(
                UserConsentConfiguration.builder()
                    .descriptionTexts(
                        UserConsentDescriptionTexts.builder()
                            .claims(Collections.emptyMap())
                            .build())
                    .build())
            .scopesConfiguration(Map.of("openid", openidConfig, "pairing", pairingConfig))
            .build();
    this.challengeToken =
        authenticationChallengeBuilder
            .buildAuthenticationChallenge(
                "goo", "foo", "bar", "schmar", "openid e-rezept", "nonceValue")
            .getChallenge();
  }

  @Test
  void getBasicFlowTokenLocationTest_ExpectNoError() {
    final IdpJwe encryptedChallenge =
        getSignedChallenge().encryptAsNjwt(idpEnc.getIdentity().getCertificate().getPublicKey());
    assertThat(idpAuthenticator.getBasicFlowTokenLocation(encryptedChallenge)).contains("code=");
  }

  @SneakyThrows
  @Test
  void getBasicFlowTokenLocationTest_InvalidExpInJwe() {
    final JsonWebToken signedChallenge = getSignedChallenge();
    final IdpJwe encryptedChallenge =
        createWithPayloadAndExpiryAndEncryptWithKey(
            "{\"njwt\":\"" + signedChallenge.getRawString() + "\"}",
            Optional.of(ZonedDateTime.now().plusMinutes(4)),
            idpEnc.getIdentity().getCertificate().getPublicKey(),
            "NJWT");
    assertThatThrownBy(() -> idpAuthenticator.getBasicFlowTokenLocation(encryptedChallenge))
        .isInstanceOf(RuntimeException.class);
  }

  @SneakyThrows
  @Test
  void getBasicFlowTokenLocationTest_ExpiredExpInJwe() {
    final JsonWebToken signedChallenge = getSignedChallenge();
    final IdpJwe encryptedChallenge =
        createWithPayloadAndExpiryAndEncryptWithKey(
            "{\"njwt\":\"" + signedChallenge.getRawString() + "\"}",
            Optional.of(ZonedDateTime.now().minusMinutes(1)),
            idpEnc.getIdentity().getCertificate().getPublicKey(),
            "NJWT");
    assertThatThrownBy(() -> idpAuthenticator.getBasicFlowTokenLocation(encryptedChallenge))
        .isInstanceOf(RuntimeException.class);
  }

  private JsonWebToken getSignedChallenge() {
    return signServerChallenge(
        challengeToken.getRawString(),
        egkIdentity.getCertificate(),
        tbsData -> {
          if (egkIdentity.getPrivateKey() instanceof RSAPrivateKey) {
            return RsaSignerUtility.createRsaSignature(tbsData, egkIdentity.getPrivateKey());
          } else {
            return EcSignerUtility.createEcSignature(tbsData, egkIdentity.getPrivateKey());
          }
        });
  }

  private JsonWebToken signServerChallenge(
      final String challengeToSign,
      final X509Certificate certificate,
      final UnaryOperator<byte[]> contentSigner) {
    final JwtClaims claims = new JwtClaims();
    claims.setClaim(ClaimName.NESTED_JWT.getJoseName(), challengeToSign);
    final JsonWebSignature jsonWebSignature = new JsonWebSignature();
    jsonWebSignature.setPayload(claims.toJson());
    jsonWebSignature.setHeader("typ", "JWT");
    jsonWebSignature.setHeader("cty", "NJWT");
    jsonWebSignature.setCertificateChainHeaderValue(certificate);
    if (isEcKey(certificate.getPublicKey())) {
      jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
    } else {
      jsonWebSignature.setAlgorithmHeaderValue(RSA_PSS_USING_SHA256);
    }
    final String signedJwt =
        jsonWebSignature.getHeaders().getEncodedHeader()
            + "."
            + jsonWebSignature.getEncodedPayload()
            + "."
            + Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                    getSignatureBytes(
                        contentSigner,
                        jsonWebSignature,
                        sigData -> {
                          if (certificate.getPublicKey() instanceof RSAPublicKey) {
                            return sigData;
                          } else {
                            try {
                              return convertDerToConcatenated(sigData, 64);
                            } catch (final IOException e) {
                              throw new RuntimeException(e);
                            }
                          }
                        }));
    return new JsonWebToken(signedJwt);
  }

  private byte[] getSignatureBytes(
      final UnaryOperator<byte[]> contentSigner,
      final JsonWebSignature jsonWebSignature,
      final UnaryOperator<byte[]> signatureStripper) {
    return signatureStripper.apply(
        contentSigner.apply(
            (jsonWebSignature.getHeaders().getEncodedHeader()
                    + "."
                    + jsonWebSignature.getEncodedPayload())
                .getBytes(StandardCharsets.UTF_8)));
  }
}
