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
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CLASS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.KEY_IDENTIFIER;

import de.gematik.idp.authentication.AuthenticationChallengeVerifier;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.X509ClaimExtraction;
import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.server.data.DeviceInformation;
import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.data.RegistrationData;
import de.gematik.idp.server.devicevalidation.DeviceValidationState;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.pairing.PairingData;
import de.gematik.idp.server.pairing.PairingRepository;
import de.gematik.idp.token.JsonWebToken;
import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PairingService {

    private final PairingRepository pairingRepository;
    private final ModelMapper modelMapper;
    private final DeviceValidationService deviceValidationService;
    private final AuthenticationChallengeVerifier authenticationChallengeVerifier;


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

    public Long validateAndInsertPairingData(final JsonWebToken accessToken, final RegistrationData registrationData) {
        validateAccessTokenClaims(accessToken);
        final String idNumber = retrieveIdNumberFromAccessToken(accessToken);
        final JsonWebToken signedPairingData = new JsonWebToken(registrationData.getSignedPairingData());
        final DeviceInformation deviceInformation = registrationData.getDeviceInformation();
        final X509Certificate authCert = CryptoLoader
            .getCertificateFromPem(Base64.getDecoder().decode(registrationData.getAuthenticationCert()));
        //TODO OCSP-Check(authCert)
        checkIdNumberIntegrity(authCert, idNumber);
        authenticationChallengeVerifier
            .verifyResponseWithCertAndThrowExceptionIfFail(authCert, signedPairingData);
        final String deviceName = deviceInformation.getDeviceName();
        if (deviceValidationService.assess(deviceInformation.getDeviceType())
            .equals(DeviceValidationState.NOT_ALLOWED)) {
            throw new IdpServerException("Device validation matched with not allowed devices!",
                IdpErrorType.DEVICE_VALIDATION_NOT_ALLOWED, HttpStatus.BAD_REQUEST);
        }
        final PairingDto data = createPairingDtoFromRegistrationData(signedPairingData, idNumber,
            deviceName);
        return insertPairing(data);
    }

    public long insertPairing(final PairingDto pairingData) {
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

