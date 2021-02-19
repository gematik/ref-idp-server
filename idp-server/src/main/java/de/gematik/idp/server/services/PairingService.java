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
import static de.gematik.idp.field.ClaimName.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.AuthenticationChallengeVerifier;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.error.IdpErrorType;
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
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PairingService {

    private static final Set<ClaimName> SIGNED_PAIRING_DATA_CLAIMS = Set
        .of(KEY_DATA, KEY_IDENTIFIER, DEVICE_PRODUCT, CERTIFICATE_SERIALNUMBER, CERTIFICATE_ISSUER,
            CERTIFICATE_NOT_AFTER, CERTIFICATE_PUBLIC_KEY, SIGNATURE_ALGORITHM_IDENTIFIER);
    private final PairingRepository pairingRepository;
    private final ModelMapper modelMapper;
    private final DeviceValidationService deviceValidationService;
    private final AuthenticationChallengeVerifier authenticationChallengeVerifier;
    private final IdpKey idpEnc;
    private final Validator validator;

    public List<PairingDto> validateTokenAndGetPairingList(final JsonWebToken accessToken) {
        validateAccessTokenClaims(accessToken);
        final List<PairingData> pairingDataList = getPairingList(retrieveIdNumberFromAccessToken(accessToken));
        return pairingDataList.stream()
            .map(this::convertToDto)
            .collect(Collectors.toList());
    }

    public List<PairingData> getPairingList(final String idNumber) {
        return pairingRepository
            .findByIdNumber(idNumber);
    }

    public void validateTokenAndDeleteSelectedPairing(final JsonWebToken accessToken, final String keyIdentifier) {
        validateAccessTokenClaims(accessToken);
        deleteSelectedPairing(retrieveIdNumberFromAccessToken(accessToken), keyIdentifier);
    }

    public void deleteSelectedPairing(final String idNumber, final String keyIdentifier) {
        pairingRepository
            .deleteByIdNumberAndKeyIdentifier(idNumber, keyIdentifier);
    }

    public void deleteAllPairing(final String idNumber) {
        pairingRepository.deleteByIdNumber(idNumber);
    }

    public Long validateAndInsertPairingData(final JsonWebToken accessToken, final IdpJwe encryptedRegistrationData) {
        final RegistrationData registrationData = decryptAndValidateRegistrationData(encryptedRegistrationData);

        validateAccessTokenClaims(accessToken);
        final String idNumber = retrieveIdNumberFromAccessToken(accessToken);
        final JsonWebToken signedPairingData = new JsonWebToken(registrationData.getSignedPairingData());
        final DeviceInformation deviceInformation = registrationData.getDeviceInformation();
        final X509Certificate authCert = CryptoLoader
            .getCertificateFromPem(Base64.getDecoder().decode(registrationData.getAuthenticationCert()));
        //TODO OCSP-Check(authCert)
        checkIdNumberIntegrity(authCert, idNumber);
        checkSignedPairingDataClaims(signedPairingData);
        authenticationChallengeVerifier
            .verifyResponseWithCertAndThrowExceptionIfFail(authCert, signedPairingData);
        if (deviceValidationService.assess(deviceInformation.getDeviceType())
            .equals(DeviceValidationState.NOT_ALLOWED)) {
            throw new IdpServerException("Device validation matched with not allowed devices!",
                IdpErrorType.DEVICE_VALIDATION_NOT_ALLOWED, HttpStatus.BAD_REQUEST);
        }
        final PairingDto data = createPairingDtoFromRegistrationData(signedPairingData, idNumber,
            deviceInformation.getDeviceName());
        return insertPairing(data);
    }

    private RegistrationData decryptAndValidateRegistrationData(final IdpJwe encryptedRegistrationData) {
        try {
            final String payload = encryptedRegistrationData.decryptJweAndReturnPayloadString(
                idpEnc.getIdentity().getPrivateKey());
            final RegistrationData registrationData = new ObjectMapper().readValue(payload, RegistrationData.class);
            final Set<ConstraintViolation<RegistrationData>> validationViolations = validator
                .validate(registrationData);
            if (!validationViolations.isEmpty()) {
                throw new IdpServerException("Validation error found in registration_data",
                    IdpErrorType.INVALID_REQUEST,
                    HttpStatus.BAD_REQUEST);
            }
            return registrationData;
        } catch (final JsonProcessingException e) {
            throw new IdpServerInvalidRequestException("Invalid Registration Data");
        }
    }

    private void checkSignedPairingDataClaims(final JsonWebToken signedPairingData) {
        final Optional<ClaimName> missingClaim = SIGNED_PAIRING_DATA_CLAIMS
            .stream()
            .filter(claimName -> signedPairingData.getBodyClaim(claimName).isEmpty())
            .findAny();
        if (missingClaim.isPresent()) {
            throw new IdpServerException(
                "Unable to find " + missingClaim.get().getJoseName() + " in signed_pairing_data",
                IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST);
        }
    }

    public long insertPairing(final PairingDto pairingData) {
        if (pairingRepository.findByIdNumberAndKeyIdentifier(pairingData.getIdNumber(), pairingData.getKeyIdentifier())
            .isPresent()) {
            throw new IdpServerException("Pairing for this ID/Key-ID combination already in DB",
                IdpErrorType.INVALID_REQUEST, HttpStatus.CONFLICT);
        }
        return pairingRepository.save(convertToEntity(pairingData)).getId();
    }

    public String retrieveIdNumberFromAccessToken(final JsonWebToken accessToken) {
        return accessToken
            .getStringBodyClaim(ClaimName.ID_NUMBER)
            .orElseThrow(() -> new IdpServerException("idNumber not found in accessToken",
                MISSING_PARAMETERS, HttpStatus.BAD_REQUEST));
    }

    private void validateAccessTokenClaims(final JsonWebToken accessToken) {
        //TODO further validation of AMR/ACR
        accessToken.getStringBodyClaim(AUTHENTICATION_METHODS_REFERENCE)
            .orElseThrow(() -> new IdpServerException("Claim amr not found in accessToken",
                MISSING_PARAMETERS, HttpStatus.BAD_REQUEST));
        accessToken.getStringBodyClaim(AUTHENTICATION_CLASS_REFERENCE)
            .orElseThrow(() -> new IdpServerException("Claim acr not found in accessToken",
                MISSING_PARAMETERS, HttpStatus.BAD_REQUEST));
    }

    private PairingDto createPairingDtoFromRegistrationData(final JsonWebToken signedPairingData, final String idNumber,
        final String deviceName) {
        return PairingDto.builder()
            .id(null)
            .idNumber(idNumber)
            .keyIdentifier(signedPairingData.getStringBodyClaim(KEY_IDENTIFIER)
                .orElseThrow(() -> new IdpServerException("Key identifier not found in pairing data",
                    MISSING_PARAMETERS, HttpStatus.BAD_REQUEST)))
            .deviceName(deviceName)
            .signedPairingData(signedPairingData.getRawString())
            .timestampPairing(ZonedDateTime.now())
            .build();
    }

    private void checkIdNumberIntegrity(final X509Certificate authCert, final String idNumber) {
        final Map<String, Object> certClaims = X509ClaimExtraction
            .extractClaimsFromCertificate(
                authCert);
        final String idNumberCert = getIdNumberFromCertClaimsAndThrowExceptionIfNotExists(certClaims);
        if (!idNumber.equals(idNumberCert)) {
            throw new IdpServerException("IdNumber does not match to certificate!",
                IdpErrorType.INVALID_PARAMETER_VALUE, HttpStatus.BAD_REQUEST);
        }
    }

    private String getIdNumberFromCertClaimsAndThrowExceptionIfNotExists(final Map<String, Object> certClaims) {
        final Optional<String> idNumber = Optional.ofNullable(certClaims.get(ClaimName.ID_NUMBER.getJoseName()))
            .filter(String.class::isInstance).map(String.class::cast);
        return idNumber.orElseThrow(() -> new IdpServerException("Information ID_NUMBER not found in certificate",
            MISSING_PARAMETERS, HttpStatus.BAD_REQUEST));
    }

    public Optional<PairingDto> getPairingDtoForIdNumberAndKeyIdentifier(final String kvnr,
        final String keyIdentifier) {
        return pairingRepository
            .findByIdNumberAndKeyIdentifier(kvnr, keyIdentifier)
            .map(this::convertToDto);
    }

    private PairingDto convertToDto(final PairingData pairingData) {
        return modelMapper.map(pairingData, PairingDto.class);
    }

    private PairingData convertToEntity(final PairingDto pairingDto) {
        return modelMapper.map(pairingDto, PairingData.class);
    }
}

