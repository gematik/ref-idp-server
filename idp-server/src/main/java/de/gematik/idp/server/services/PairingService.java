/*
 * Copyright (c) 2021 gematik GmbH
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
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.exceptions.ChallengeSignatureInvalidException;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.data.DeviceInformation;
import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.data.RegistrationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationState;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidRequestException;
import de.gematik.idp.server.pairing.PairingData;
import de.gematik.idp.server.pairing.PairingRepository;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;
import javax.validation.ConstraintViolation;
import javax.validation.Validator;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PairingService {

    private static final Set<ClaimName> SIGNED_PAIRING_DATA_CLAIMS = Set
        .of(CERTIFICATE_NOT_AFTER, AUTH_CERT_SUBJECT_PUBLIC_KEY_INFO, CERTIFICATE_SERIALNUMBER, KEY_IDENTIFIER,
            SE_SUBJECT_PUBLIC_KEY_INFO, CERTIFICATE_ISSUER, DEVICE_PRODUCT);
    private final PairingRepository pairingRepository;
    private final DeviceValidationService deviceValidationService;
    private final AuthenticationChallengeVerifier authenticationChallengeVerifier;
    private final IdpKey idpEnc;
    private final Validator validator;
    private final DataVersionService dataVersionService;

    public List<PairingDto> validateTokenAndGetPairingList(final JsonWebToken accessToken) {
        validateAccessTokenClaims(accessToken);
        final List<PairingData> pairingDataList = getPairingList(retrieveIdNumberFromAccessToken(accessToken));
        return pairingDataList.stream()
            .map(this::convertToDto)
            .collect(Collectors.toList());
    }

    public List<PairingData> getPairingList(final String idNumber) {
        return pairingRepository.findByIdNumber(idNumber);
    }

    public void validateTokenAndDeleteSelectedPairing(final JsonWebToken accessToken, final String keyIdentifier) {
        validateAccessTokenClaims(accessToken);
        deleteSelectedPairing(retrieveIdNumberFromAccessToken(accessToken), keyIdentifier);
    }

    public void deleteSelectedPairing(final String idNumber, final String keyIdentifier) {
        final long result = pairingRepository
            .deleteByIdNumberAndKeyIdentifier(idNumber, keyIdentifier);
        if (result == 0) {
            throw new IdpServerException(4000, IdpErrorType.INVALID_REQUEST,
                "Der Auftrag zur Deaktivierung des Pairings konnte nicht angenommen werden.", HttpStatus.BAD_REQUEST);
        }
    }

    public void deleteAllPairing(final String idNumber) {
        pairingRepository.deleteByIdNumber(idNumber);
    }

    public PairingDto validatePairingData(final JsonWebToken accessToken,
        final IdpJwe encryptedRegistrationData) {
        final RegistrationData registrationData = decryptAndValidateRegistrationData(encryptedRegistrationData);

        validateAccessTokenClaims(accessToken);
        final String idNumber = retrieveIdNumberFromAccessToken(accessToken);
        final JsonWebToken signedPairingData = new JsonWebToken(registrationData.getSignedPairingData());
        final DeviceInformation deviceInformation = registrationData.getDeviceInformation();

        dataVersionService.checkDataVersion(deviceInformation);
        dataVersionService.checkDataVersion(deviceInformation.getDeviceType());

        final X509Certificate authCert = CryptoLoader
            .getCertificateFromPem(Base64.getUrlDecoder().decode(registrationData.getAuthCert()));
        checkIdNumberIntegrity(authCert, idNumber);
        checkSignedPairingDataClaims(signedPairingData);
        try {
            authenticationChallengeVerifier
                .verifyResponseWithCertAndThrowExceptionIfFail(authCert, signedPairingData);
        } catch (final ChallengeSignatureInvalidException csie) {
            throw new IdpServerException(IdpServerException.ERROR_ID_ACCESS_DENIED, IdpErrorType.ACCESS_DENIED,
                "Challenge signature invalid!", HttpStatus.FORBIDDEN, csie);
        }
        if (deviceValidationService.assess(deviceInformation.getDeviceType())
            .equals(DeviceValidationState.BLOCK)) {
            throw new IdpServerException(IdpServerException.ERROR_ID_BLOCKLIST, IdpErrorType.ACCESS_DENIED,
                "Device validation matched with not allowed devices!", HttpStatus.BAD_REQUEST);
        }
        final PairingData data = createPairingDtoFromRegistrationData(signedPairingData, idNumber,
            deviceInformation.getName());
        return convertToDto(insertPairing(data));
    }

    private RegistrationData decryptAndValidateRegistrationData(final IdpJwe encryptedRegistrationData) {
        try {
            final String payload = encryptedRegistrationData.decryptJweAndReturnPayloadString(
                idpEnc.getIdentity().getPrivateKey());
            final RegistrationData registrationData = new ObjectMapper().readValue(payload, RegistrationData.class);
            final Set<ConstraintViolation<RegistrationData>> validationViolations = validator
                .validate(registrationData);
            if (!validationViolations.isEmpty()) {
                throw new IdpServerException(IdpServerException.ERROR_ID_ACCESS_DENIED,
                    IdpErrorType.ACCESS_DENIED,
                    "Validation error found in registration_data", HttpStatus.FORBIDDEN);
            }
            dataVersionService.checkDataVersion(registrationData);

            return registrationData;
        } catch (final JsonProcessingException e) {
            throw new IdpServerInvalidRequestException("Invalid Registration Data", e);
        }
    }

    private void checkSignedPairingDataClaims(final JsonWebToken signedPairingData) {
        final Optional<ClaimName> missingClaim = SIGNED_PAIRING_DATA_CLAIMS
            .stream()
            .filter(claimName -> signedPairingData.getBodyClaim(claimName).isEmpty())
            .findAny();
        if (missingClaim.isPresent()) {
            throw new IdpServerException(IdpServerException.ERROR_ID_ACCESS_DENIED, IdpErrorType.ACCESS_DENIED,
                "Unable to find " + missingClaim.get().getJoseName() + " in signed_pairing_data",
                HttpStatus.FORBIDDEN);
        }
        dataVersionService.checkSignedPairingDataVersion(signedPairingData);
    }

    public PairingData insertPairing(final PairingData pairingData) {
        if (pairingRepository.findByIdNumberAndKeyIdentifier(pairingData.getIdNumber(), pairingData.getKeyIdentifier())
            .isPresent()) {
            throw new IdpServerException(4004, IdpErrorType.INVALID_REQUEST,
                "Pairing for this ID/Key-ID combination already in DB", HttpStatus.CONFLICT);
        }
        return pairingRepository.save(pairingData);
    }

    public String retrieveIdNumberFromAccessToken(final JsonWebToken accessToken) {
        return accessToken
            .getStringBodyClaim(ClaimName.ID_NUMBER)
            .orElseThrow(() -> new IdpServerException("idNumber not found in accessToken",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST));
    }

    private void validateAccessTokenClaims(final JsonWebToken accessToken) {
        if (accessToken.getBodyClaim(AUTHENTICATION_METHODS_REFERENCE).isEmpty()) {
            throw new IdpServerException("Claim amr not found in accessToken",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST);
        }
        if (accessToken.getBodyClaim(AUTHENTICATION_CLASS_REFERENCE).isEmpty()) {
            throw new IdpServerException("Claim acr not found in accessToken",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST);
        }
    }

    private PairingData createPairingDtoFromRegistrationData(final JsonWebToken signedPairingData,
        final String idNumber,
        final String deviceName) {
        return PairingData.builder()
            .id(null)
            .idNumber(idNumber)
            .keyIdentifier(signedPairingData.getStringBodyClaim(KEY_IDENTIFIER)
                .orElseThrow(() -> new IdpServerException("Key identifier not found in pairing data",
                    IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST)))
            .deviceName(deviceName)
            .signedPairingData(signedPairingData.getRawString())
            .timestampPairing(ZonedDateTime.now())
            .build();
    }

    private void checkIdNumberIntegrity(final X509Certificate authCert, final String idNumber) {
        try {
            final Map<String, Object> certClaims = X509ClaimExtraction
                .extractClaimsFromCertificate(
                    authCert);
            final String idNumberCert = getIdNumberFromCertClaimsAndThrowExceptionIfNotExists(certClaims);
            if (!idNumber.equals(idNumberCert)) {
                throw new IdpServerException(IdpServerException.ERROR_ID_ACCESS_DENIED, IdpErrorType.ACCESS_DENIED,
                    "IdNumber does not match to certificate!", HttpStatus.FORBIDDEN);
            }
        } catch (final IdpServerException ise) {
            throw ise;
        } catch (final Exception e) {
            throw new IdpServerException(IdpServerException.ERROR_ID_ACCESS_DENIED, IdpErrorType.ACCESS_DENIED,
                "Error while extracting claim from certificate!", HttpStatus.FORBIDDEN);
        }
    }

    private String getIdNumberFromCertClaimsAndThrowExceptionIfNotExists(final Map<String, Object> certClaims) {
        final Optional<String> idNumber = Optional.ofNullable(certClaims.get(ClaimName.ID_NUMBER.getJoseName()))
            .filter(String.class::isInstance).map(String.class::cast);
        return idNumber.orElseThrow(() -> new IdpServerException(IdpServerException.ERROR_ID_ACCESS_DENIED,
            IdpErrorType.ACCESS_DENIED,
            "Information ID_NUMBER not found in certificate", HttpStatus.FORBIDDEN));
    }

    public Optional<PairingDto> getPairingDtoForIdNumberAndKeyIdentifier(final String kvnr,
        final String keyIdentifier) {
        return pairingRepository
            .findByIdNumberAndKeyIdentifier(kvnr, keyIdentifier)
            .map(this::convertToDto);
    }

    private PairingDto convertToDto(final PairingData pairingData) {

        return PairingDto.builder()
            .creationTime(pairingData.getTimestampPairing().toEpochSecond())
            .signedPairingData(pairingData.getSignedPairingData())
            .name(pairingData.getDeviceName())
            .pairingEntryVersion(dataVersionService.getCurrentVersion())
            .build();
    }
}
