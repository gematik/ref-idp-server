/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.client;

import static de.gematik.idp.IdpConstants.DEFAULT_SERVER_URL;
import static de.gematik.idp.IdpConstants.EREZEPT;
import static de.gematik.idp.IdpConstants.OPENID;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;

import de.gematik.idp.authentication.AuthenticationChallenge;
import de.gematik.idp.authentication.AuthenticationChallengeBuilder;
import de.gematik.idp.authentication.AuthenticationResponse;
import de.gematik.idp.authentication.AuthenticationResponseBuilder;
import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.ScopeConfiguration;
import de.gematik.idp.data.UserConsentConfiguration;
import de.gematik.idp.data.UserConsentDescriptionTexts;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.AccessTokenBuilder;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import javax.crypto.spec.SecretKeySpec;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

@Getter
@EqualsAndHashCode
@ToString
@AllArgsConstructor
@Builder(toBuilder = true)
public class MockIdpClient implements IIdpClient {

  private static final String SERVER_SUB_SALT = "someArbitrarySubSaltValue";

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
    BrainpoolCurves.init();
  }

  private final PkiIdentity serverIdentity;
  private final String clientId;
  private final boolean produceTokensWithInvalidSignature;
  private final boolean produceOnlyExpiredTokens;
  @Builder.Default private final String uriIdpServer = DEFAULT_SERVER_URL;
  private final HashMap<String, String> scopeToAudienceUrls = new HashMap<>();
  private AccessTokenBuilder accessTokenBuilder;
  private AuthenticationResponseBuilder authenticationResponseBuilder;
  private AuthenticationTokenBuilder authenticationTokenBuilder;
  private AuthenticationChallengeBuilder authenticationChallengeBuilder;
  private IdpJwtProcessor jwtProcessor;
  private SecretKeySpec encryptionKey;

  @Override
  public IdpTokenResult login(final PkiIdentity clientIdentity) {
    assertThatMockIdClientIsInitialized();

    return IdpTokenResult.builder()
        .accessToken(buildAccessToken(clientIdentity))
        .validUntil(LocalDateTime.now().plusMinutes(5))
        .build();
  }

  private JsonWebToken buildAccessToken(final PkiIdentity clientIdentity) {
    final AuthenticationChallenge challenge =
        authenticationChallengeBuilder.buildAuthenticationChallenge(
            clientId, "placeholderValue", "foo", "foo", OPENID + " " + EREZEPT, "nonceValue");
    final AuthenticationResponse authenticationResponse =
        authenticationResponseBuilder.buildResponseForChallenge(challenge, clientIdentity);
    final IdpJwe authenticationToken =
        authenticationTokenBuilder.buildAuthenticationToken(
            clientIdentity.getCertificate(),
            authenticationResponse
                .getSignedChallenge()
                .getBodyClaim(ClaimName.NESTED_JWT)
                .map(Objects::toString)
                .map(JsonWebToken::new)
                .map(JsonWebToken::getBodyClaims)
                .orElseThrow(),
            ZonedDateTime.now());

    JsonWebToken accessToken =
        accessTokenBuilder.buildAccessToken(authenticationToken.decryptNestedJwt(encryptionKey));

    if (produceOnlyExpiredTokens) {
      accessToken =
          resignToken(
              accessToken.getHeaderClaims(),
              accessToken.getBodyClaims(),
              ZonedDateTime.now().minusMinutes(10));
    }

    if (produceTokensWithInvalidSignature) {
      final List<String> strings = Arrays.asList(accessToken.getRawString().split("\\."));
      strings.set(2, strings.get(2) + "mvK");
      accessToken = new JsonWebToken(strings.stream().collect(Collectors.joining(".")));
    }

    return accessToken;
  }

  public JsonWebToken resignToken(
      final Map<String, Object> headerClaims,
      final Map<String, Object> bodyClaims,
      final ZonedDateTime expiresAt) {
    Objects.requireNonNull(jwtProcessor, "jwtProcessor is null. Did you call initialize()?");
    return jwtProcessor.buildJwt(
        new JwtBuilder()
            .addAllBodyClaims(bodyClaims)
            .addAllHeaderClaims(headerClaims)
            .expiresAt(expiresAt));
  }

  @Override
  public MockIdpClient initialize() {
    scopeToAudienceUrls.put("e-rezept", "https://erp-test.zentral.erp.splitdns.ti-dienste.de/");
    scopeToAudienceUrls.put(
        "pairing", "https://idp-pairing-test.zentral.idp.splitdns.ti-dienste.de");

    final ScopeConfiguration openidConfig =
        ScopeConfiguration.builder().description("Zugriff auf den ID-Token.").build();
    final ScopeConfiguration pairingConfig =
        ScopeConfiguration.builder()
            .audienceUrl("https://idp-pairing-test.zentral.idp.splitdns.ti-dienste.de")
            .description("Zugriff auf die Daten für die biometrischer Authentisierung.")
            .claimsToBeIncluded(List.of(ID_NUMBER))
            .build();
    final ScopeConfiguration erezeptConfig =
        ScopeConfiguration.builder()
            .audienceUrl("https://erp-test.zentral.erp.splitdns.ti-dienste.de/")
            .description("Zugriff auf die E-Rezept-Funktionalität.")
            .claimsToBeIncluded(
                List.of(GIVEN_NAME, FAMILY_NAME, ORGANIZATION_NAME, PROFESSION_OID, ID_NUMBER))
            .build();

    //    serverIdentity.setUse(Optional.of("sig"));
    final java.util.Optional<String> keyId = java.util.Optional.of("puk_idp_sig");
    jwtProcessor = new IdpJwtProcessor(serverIdentity, keyId);
    accessTokenBuilder =
        new AccessTokenBuilder(jwtProcessor, uriIdpServer, SERVER_SUB_SALT, scopeToAudienceUrls);
    authenticationChallengeBuilder =
        AuthenticationChallengeBuilder.builder()
            .serverSigner(new IdpJwtProcessor(serverIdentity, keyId))
            .uriIdpServer(uriIdpServer)
            .userConsentConfiguration(
                UserConsentConfiguration.builder()
                    .descriptionTexts(
                        UserConsentDescriptionTexts.builder()
                            .claims(Collections.emptyMap())
                            .build())
                    .build())
            .scopesConfiguration(
                Map.of("openid", openidConfig, "erezept", erezeptConfig, "pairing", pairingConfig))
            .build();
    authenticationResponseBuilder = new AuthenticationResponseBuilder();
    encryptionKey = new SecretKeySpec(DigestUtils.sha256("fdsa"), "AES");
    authenticationTokenBuilder =
        AuthenticationTokenBuilder.builder()
            .jwtProcessor(jwtProcessor)
            .encryptionKey(encryptionKey)
            .build();
    return this;
  }

  private void assertThatMockIdClientIsInitialized() {
    Objects.requireNonNull(
        accessTokenBuilder, "accessTokenBuilder is null. Did you call initialize()?");
    Objects.requireNonNull(
        authenticationTokenBuilder,
        "authenticationTokenBuilder is null. Did you call initialize()?");
    Objects.requireNonNull(clientId, "clientId is null. You have to set it!");
  }
}
