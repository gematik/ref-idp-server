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

import static de.gematik.idp.field.ClaimName.AUTHENTICATION_DATA_VERSION;
import static de.gematik.idp.field.ClaimName.PAIRING_DATA_VERSION;

import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.data.DataVersion;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.token.JsonWebToken;
import java.util.Optional;
import java.util.function.Predicate;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DataVersionService {

    private static final String ALLOWED_VERSION = "1.0";

    public void checkDataVersion(final DataVersion dataVersion) {
        checkVersion(Optional.ofNullable(dataVersion.getDataVersion()), dataVersion.getClass().getSimpleName());
    }

    public void checkSignedAuthDataVersion(final JsonWebToken signedAuthData) {
        checkVersion(signedAuthData.getStringBodyClaim(AUTHENTICATION_DATA_VERSION), "Authentication data");
    }

    private void checkVersion(final Optional<String> checkVersion, final String type) {
        final boolean versionOk = checkVersion
            .filter(Predicate.not(String::isBlank))
            .filter(ALLOWED_VERSION::equals)
            .isPresent();
        if (!versionOk) {
            throw new IdpServerException(String.format("%s version is not supported!", type),
                IdpErrorType.INVALID_REQUEST,
                HttpStatus.BAD_REQUEST);
        }
    }

    public void checkSignedPairingDataVersion(final JsonWebToken signedPairingData) {
        checkVersion(signedPairingData.getStringBodyClaim(PAIRING_DATA_VERSION), "Pairing data");
    }

    public String getCurrentVersion() {
        return ALLOWED_VERSION;
    }
}
