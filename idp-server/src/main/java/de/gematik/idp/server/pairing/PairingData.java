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

package de.gematik.idp.server.pairing;

import java.time.ZonedDateTime;
import javax.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "pairing", schema = "IDP")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PairingData {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "id_number")
    private String idNumber;
    @Column(name = "key_identifier")
    private String keyIdentifier;
    @Column(name = "device_name")
    private String deviceName;
    @Column(name = "signed_pairing_data")
    private String signedPairingData;
    @Column(name = "timestamp_pairing")
    private ZonedDateTime timestampPairing;

}
