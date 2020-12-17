/*
 * Copyright (c) 2020 gematik GmbH
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

package de.gematik.idp.authentication;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.token.JsonWebToken;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.lang.JoseException;

import java.security.cert.X509Certificate;
import java.util.Map;

@Data
@Builder
@AllArgsConstructor
public class AuthenticationChallengeVerifier {

    private PkiIdentity serverIdentity;

    public void verifyResponseAndThrowExceptionIfFail(final JsonWebToken authenticationResponse) {
        final JwtContext jwtContext = processChallenge(authenticationResponse);
        final X509Certificate clientCertificate = extractClientCertificateFromChallenge(jwtContext);
        performSignatureValidation(clientCertificate, authenticationResponse.getJwtRawString());
    }

    private void performSignatureValidation(final X509Certificate clientCertificate,
                                            final String authResponse) {
        final JwtConsumer serverJwtConsumer = new JwtConsumerBuilder()
                .setVerificationKey(clientCertificate.getPublicKey())
                .build();
        try {
            serverJwtConsumer.process(authResponse);
        } catch (final InvalidJwtException e) {
            throw new IdpJoseException(e);
        }
    }

    public X509Certificate extractClientCertificateFromChallenge(final JwtContext jwtContext) {
        try {
            return jwtContext.getJoseObjects().get(0).getCertificateChainHeaderValue()
                    .stream()
                    .findFirst()
                    .orElseThrow(() -> new IdpJoseException("Failure to get PublicKey"));
        } catch (final JoseException e) {
            throw new IdpJoseException("Structure of given JWT is unexpected", e);
        }
    }

    private JwtContext processChallenge(final JsonWebToken signedChallenge) {
        final JwtConsumer serverJwtConsumer = new JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipDefaultAudienceValidation()
                .build();
        try {
            return serverJwtConsumer.process(signedChallenge.getJwtRawString());
        } catch (final InvalidJwtException e) {
            throw new IdpJoseException(e);
        }
    }

    public Map<String, Object> extractClaimsFromSignedChallenge(final AuthenticationResponse authenticationResponse) {
        return processChallenge(authenticationResponse.getSignedChallenge())
                .getJwtClaims().getClaimsMap();
    }
}
