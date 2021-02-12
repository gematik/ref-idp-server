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

package de.gematik.idp.client.data;

import java.time.ZonedDateTime;
import lombok.*;

@ToString
@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class BiometrieData {

    @Builder.Default
    private String id = "";
    @Builder.Default
    private String idNumber = "anyIdNumber";
    @Builder.Default
    private String keyIdentifier = "anyKeyIdentifier";
    @Builder.Default
    private String signatureAlgorithm = "anySignatureAlgorithm";
    @Builder.Default
    private String signature = "anySignature";
    @Builder.Default
    private String authorityInfoAccess = "anyAuthorityInfoAccess";
    @Builder.Default
    private String certId = "anyCertId";
    @Builder.Default
    private String publicKey = "anyPublicKey";
    @Builder.Default
    private String product = "anyProduct";
    @Builder.Default
    private String deviceName = "anyDeviceName";
    @Builder.Default
    private String keyDataAlgorithm = "anyKeyDataAlgorithm";
    @Builder.Default
    private String keyData = "anyKeyData";
    @Builder.Default
    private ZonedDateTime timestampPairing = ZonedDateTime.now();

}
