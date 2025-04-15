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

package de.gematik.idp.authentication;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;

import de.gematik.idp.exceptions.ChallengeExpiredException;
import de.gematik.idp.exceptions.ChallengeSignatureInvalidException;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.exceptions.NoNestedJwtFoundException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

@Data
@Builder
@AllArgsConstructor
public class AuthenticationChallengeVerifier {

  private PublicKey serverPublicKey;

  public void verifyResponseAndThrowExceptionIfFail(final JsonWebToken authenticationResponse) {
    final X509Certificate clientCertificate =
        extractClientCertificateFromChallenge(authenticationResponse)
            .orElseThrow(
                () ->
                    new IdpJoseException(
                        "Could not extract client certificate from challenge response header"));

    performClientSignatureValidation(clientCertificate, authenticationResponse.getRawString());
    performServerSignatureValidationOfNjwt(authenticationResponse);
  }

  public void verifyResponseWithCertAndThrowExceptionIfFail(
      final X509Certificate authCert, final JsonWebToken authenticationResponse) {
    performClientSignatureValidation(authCert, authenticationResponse.getRawString());
  }

  private void performClientSignatureValidation(
      final X509Certificate clientCertificate, final String authResponse) {
    final JwtConsumer serverJwtConsumer =
        new JwtConsumerBuilder()
            .setVerificationKey(clientCertificate.getPublicKey())
            .setSkipDefaultAudienceValidation()
            .setJwsAlgorithmConstraints(
                (new AlgorithmConstraints(
                    ConstraintType.PERMIT,
                    AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
                    BRAINPOOL256_USING_SHA256)))
            .build();
    try {
      serverJwtConsumer.process(authResponse);
    } catch (final Exception e) {
      throw new ChallengeSignatureInvalidException(e);
    }
  }

  private void performServerSignatureValidationOfNjwt(final JsonWebToken authenticationResponse) {
    final JsonWebToken serverChallenge =
        authenticationResponse
            .getBodyClaim(ClaimName.NESTED_JWT)
            .map(njwt -> new JsonWebToken(njwt.toString()))
            .orElseThrow(NoNestedJwtFoundException::new);

    if (serverChallenge.getExpiresAt().isBefore(ZonedDateTime.now())
        || serverChallenge.getExpiresAtBody().isBefore(ZonedDateTime.now())) {
      throw new ChallengeExpiredException();
    }
    try {
      serverChallenge.verify(serverPublicKey);
    } catch (final Exception e) {
      throw new ChallengeSignatureInvalidException();
    }
  }

  public Optional<X509Certificate> extractClientCertificateFromChallenge(
      final JsonWebToken authenticationResponse) {
    return authenticationResponse.getClientCertificateFromHeader();
  }

  public Map<String, Object> extractClaimsFromSignedChallenge(
      final AuthenticationResponse authenticationResponse) {
    return authenticationResponse.getSignedChallenge().getBodyClaims();
  }
}
