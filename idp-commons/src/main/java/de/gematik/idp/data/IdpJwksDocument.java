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

package de.gematik.idp.data;

import de.gematik.idp.brainPoolExtension.BrainpoolCurves;
import de.gematik.idp.crypto.model.PkiIdentity;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Data
public class IdpJwksDocument {

    private List<IdpKeyDescriptor> keys;

    {
        BrainpoolCurves.init();
    }

    public static IdpJwksDocument constructFromX509Certificate(final PkiIdentity... identities) {
        return IdpJwksDocument.builder()
            .keys(Stream.of(identities)
                .map(identity -> IdpKeyDescriptor.constructFromX509Certificate(identity.getCertificate(),
                    identity.getKeyId()))
                .collect(Collectors.toList()))
            .build();
    }
}
