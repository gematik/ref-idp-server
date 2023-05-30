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

package de.gematik.idp.authentication;

import static de.gematik.idp.brainPoolExtension.BrainpoolAlgorithmSuiteIdentifiers.BRAINPOOL256_USING_SHA256;
import static de.gematik.idp.crypto.KeyAnalysis.isEcKey;
import static org.jose4j.jws.AlgorithmIdentifiers.RSA_PSS_USING_SHA256;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpRuntimeException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.JsonWebToken;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;

@Data
@Builder
@AllArgsConstructor
public class AuthenticationResponseBuilder {

  public AuthenticationResponse buildResponseForChallenge(
      final AuthenticationChallenge authenticationChallenge, final PkiIdentity clientIdentity) {
    final JwtClaims claims = new JwtClaims();
    claims.setClaim(
        ClaimName.NESTED_JWT.getJoseName(), authenticationChallenge.getChallenge().getRawString());

    final JsonWebSignature jsonWebSignature = new JsonWebSignature();
    jsonWebSignature.setPayload(claims.toJson());

    if (isEcKey(clientIdentity.getCertificate().getPublicKey())) {
      jsonWebSignature.setAlgorithmHeaderValue(BRAINPOOL256_USING_SHA256);
    } else {
      jsonWebSignature.setAlgorithmHeaderValue(RSA_PSS_USING_SHA256);
    }
    jsonWebSignature.setKey(clientIdentity.getPrivateKey());

    jsonWebSignature.setHeader("typ", "JWT");
    jsonWebSignature.setHeader("cty", "NJWT");
    jsonWebSignature.setCertificateChainHeaderValue(clientIdentity.getCertificate());

    try {
      final String compactSerialization = jsonWebSignature.getCompactSerialization();
      return AuthenticationResponse.builder()
          .signedChallenge(new JsonWebToken(compactSerialization))
          .build();
    } catch (final JoseException e) {
      throw new IdpRuntimeException(e);
    }
  }
}
