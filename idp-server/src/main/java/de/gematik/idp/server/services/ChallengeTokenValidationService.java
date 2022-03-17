/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.server.services;

import static de.gematik.idp.field.ClaimName.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.AuthenticationChallengeVerifier;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.data.IdpErrorResponse;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.field.AuthenticationMethodReference;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.data.DeviceInformation;
import de.gematik.idp.server.devicevalidation.DeviceValidationState;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.pairing.PairingData;
import de.gematik.idp.server.pairing.PairingRepository;
import de.gematik.idp.token.JsonWebToken;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service
public class ChallengeTokenValidationService {

    private final PairingRepository pairingRepository;
    private final AuthenticationChallengeVerifier authenticationChallengeVerifier;
    private final DeviceValidationService deviceValidationService;
    private final DataVersionService dataVersionService;

    public void validateChallengeToken(final JsonWebToken signedChallenge) {
        final Set<String> amr = signedChallenge.getBodyClaim(ClaimName.AUTHENTICATION_METHODS_REFERENCE)
            .filter(List.class::isInstance)
            .map(List.class::cast)
            .stream()
            .flatMap(List<String>::stream)
            .collect(Collectors.toSet());
        final boolean isAltAuth = amr.containsAll(Arrays.asList("mfa", "hwk")) &&
                (amr.contains("fpt") || amr.contains("face") || amr.contains("pin") ||
                        amr.contains("pwd") || amr.contains("generic-biometric") || amr.contains("kba"));
        if (isAltAuth) {
            try {
                validateAlternateAuthenticationDataAndThrowExceptionIfFail(signedChallenge);
            } catch (final RuntimeException e) {
                throw new IdpServerException(2000, IdpErrorType.ACCESS_DENIED, e.getMessage(), e);
            }
        } else {
            authenticationChallengeVerifier.verifyResponseAndThrowExceptionIfFail(signedChallenge);
        }
    }

    private void validateAlternateAuthenticationDataAndThrowExceptionIfFail(final JsonWebToken signedAuthData) {
        final X509Certificate authDataCert = signedAuthData.getAuthenticationCertificate()
            .orElseThrow(() -> new IdpServerException("No Certificate given in authentication data!",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
        final String keyIdentifier = signedAuthData.getStringBodyClaim(KEY_IDENTIFIER).orElseThrow(
            () -> new IdpServerException("Unable to find key identifier in authentication data",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
        final String idNumber = getIdNumberFromAuthDataCertClaims(authDataCert);
        final PairingData pairingData = pairingRepository
            .findByIdNumberAndKeyIdentifier(idNumber, keyIdentifier)
            .orElseThrow(
                () -> new IdpServerException("Unable to find pairing entry with given id-number and key-identifier",
                    IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));

        dataVersionService.checkSignedAuthDataVersion(signedAuthData);

        final DeviceInformation deviceInformation = retrieveDeviceInformationFromAuthData(signedAuthData);
        dataVersionService.checkDataVersion(deviceInformation);
        dataVersionService.checkDataVersion(deviceInformation.getDeviceType());

        if (deviceValidationService.assess(deviceInformation.getDeviceType())
            .equals(DeviceValidationState.BLOCK)) {
            throw new IdpServerException("Device validation matched with not allowed devices!",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST);
        } else if (
            deviceValidationService.assess(deviceInformation.getDeviceType()).equals(DeviceValidationState.UNKNOWN)
                && pairingData.getTimestampPairing().isBefore(ZonedDateTime.now().minusMonths(6))) {
            throw new IdpServerException("Device validation failed. Pairing expired!",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST);
        }
        final JsonWebToken signedPairingDataFromDto = new JsonWebToken(pairingData.getSignedPairingData());
        signedPairingDataFromDto.verify(retrieveKeyFromPairingDto(pairingData, AUTH_CERT_SUBJECT_PUBLIC_KEY_INFO));
        validateCertSn(authDataCert, signedPairingDataFromDto.getStringBodyClaim(CERTIFICATE_SERIALNUMBER)
            .orElseThrow(() -> new IdpServerException("CertID not found in pairing data",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST)));
        signedAuthData.verify(retrieveKeyFromPairingDto(pairingData, SE_SUBJECT_PUBLIC_KEY_INFO));
    }

    private void validateCertSn(final X509Certificate authDataCert, final String pairingCertSN) {
        final String authDataCertSn = authDataCert.getSerialNumber().toString();
        if (!pairingCertSN.equals(authDataCertSn)) {
            throw new IdpServerException(4666, null, "Serial number of cert did not match pairing data");
        }
    }

    private PublicKey retrieveKeyFromPairingDto(final PairingData pairingData, final ClaimName claimName) {
        return new JsonWebToken(pairingData.getSignedPairingData())
            .getStringBodyClaim(claimName)
            .map(Base64.getUrlDecoder()::decode)
            .map(CryptoLoader::getEcPublicKeyFromBytes)
            .orElseThrow(() -> new IdpServerException("PublicKey not found in pairing data",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
    }

    public String getIdNumberFromAuthDataCertClaims(final X509Certificate authCert) {
        return Optional.ofNullable(X509ClaimExtraction
            .extractClaimsFromCertificate(authCert).get(ClaimName.ID_NUMBER.getJoseName()))
            .filter(String.class::isInstance)
            .map(String.class::cast)
            .orElseThrow(() -> new IdpServerException("Information ID_NUMBER not found in certificate",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
    }

    private DeviceInformation retrieveDeviceInformationFromAuthData(final JsonWebToken signedAuthData) {
        return signedAuthData.getBodyClaim(DEVICE_INFORMATION)
            .filter(Map.class::isInstance)
            .map(Map.class::cast)
            .map(JSONObject::new)
            .map(JSONObject::toString)
            .map(this::createDeviceInfoFromJson)
            .orElseThrow(() -> new IdpServerException("Device information not found in auth data",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
    }

    private DeviceInformation createDeviceInfoFromJson(final String json) {
        final ObjectMapper mapper = new ObjectMapper();
        final DeviceInformation deviceInformation;
        try {
            deviceInformation = mapper.readValue(json, DeviceInformation.class);
        } catch (final JsonProcessingException e) {
            throw new IdpServerException(IdpErrorResponse.builder()
                .detailMessage("Device information in auth data invalid")
                .code("4666")
                .error(null)
                .build(), e);
        }
        return deviceInformation;
    }

    private boolean isAlternateAuthentication(final String[] amr) {
        final List<String> altAuthList = Arrays.stream(AuthenticationMethodReference.values())
            .filter(AuthenticationMethodReference::isAlternativeAuthentication)
            .map(AuthenticationMethodReference::getDescription)
            .collect(Collectors.toList());
        return Arrays.stream(amr).anyMatch(altAuthList::contains);
    }
}
