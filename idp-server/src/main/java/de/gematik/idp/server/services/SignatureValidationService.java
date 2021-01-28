/*
 * Copyright (c) 2021 gematik GmbH
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

package de.gematik.idp.server.services;

import static de.gematik.idp.error.IdpErrorType.MISSING_PARAMETERS;

import de.gematik.idp.authentication.AuthenticationChallengeVerifier;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.field.AuthenticationMethodReference;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class SignatureValidationService {

    private final PairingService pairingService;
    private final AuthenticationChallengeVerifier authenticationChallengeVerifier;

    public void validateSignature(final JsonWebToken signedChallenge) {
        final boolean isBiometricAuthentication = signedChallenge
            .getStringBodyClaim(ClaimName.AUTHENTICATION_METHODS_REFERENCE)
            .map(this::isBiometric)
            .orElse(false);

        if (isBiometricAuthentication) {
            validateBiometricAndThrowExceptionIfFail(signedChallenge);
        } else {
            authenticationChallengeVerifier.verifyResponseAndThrowExceptionIfFail(signedChallenge);
        }
    }

    private boolean isBiometric(final String amr) {
        return Arrays.stream(AuthenticationMethodReference.values())
            .anyMatch(v -> v.isBiometric() && amr.contains(v.getDescription()));
    }

    private void validateBiometricAndThrowExceptionIfFail(final JsonWebToken signedChallenge) {
        final String kvnrFromChallenge = getKvnrFromChallengeAndThrowExceptionIfNotExists(signedChallenge);

        final String deviceManufacturer = signedChallenge
            .getStringBodyClaim(ClaimName.DEVICE_MANUFACTURER)
            .orElseThrow(() -> new IdpServerInvalidRequestException("Illegal token: No device-Manufacturer given"));

        final PairingDto pairingData = Optional.of(deviceManufacturer)
            .flatMap(manufacturer -> pairingService.getPairingDtoForKvnrAndDevice(kvnrFromChallenge, manufacturer))
            .orElseThrow(
                () -> new IdpServerException("Unable to find pairing entry with given kvnr and device info",
                    IdpErrorType.RESOURCE_NOT_FOUND, HttpStatus.BAD_REQUEST));

        authenticationChallengeVerifier
            .verifyResponseWithCertAndThrowExceptionIfFail(CryptoLoader
                    .getCertificateFromPem(Base64.getDecoder().decode(pairingData.getPukSeB64())),
                signedChallenge);
    }

    private String getKvnrFromChallengeAndThrowExceptionIfNotExists(final JsonWebToken signedChallenge) {
        final Optional<X509Certificate> clientCertificateFromHeader = signedChallenge.getClientCertificateFromHeader();
        final Map<String, Object> claimsMap = X509ClaimExtraction
            .extractClaimsFromCertificate(clientCertificateFromHeader
                .orElseThrow(() -> new IdpServerException("No Certificate given in header of Signed-Challenge!")));
        final String kvnr = (String) claimsMap.get(ClaimName.ID_NUMBER.getJoseName());
        if (kvnr == null) {
            throw new IdpServerException("", MISSING_PARAMETERS, HttpStatus.BAD_REQUEST);
        }
        return kvnr;
    }
}
