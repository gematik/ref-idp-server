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

package de.gematik.idp.crypto.model;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PkiIdentity {

    private X509Certificate certificate;
    private PrivateKey privateKey;

    public String getBase64EncodedCertificate() {
        try {
            return java.util.Base64.getUrlEncoder().encodeToString(certificate.getEncoded());
        } catch (final CertificateEncodingException e) {
            throw new IdpCryptoException("Error while retrieving key information", e);
        }
    }
}
