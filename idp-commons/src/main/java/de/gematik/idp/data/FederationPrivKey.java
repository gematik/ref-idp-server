/*
 * Copyright (Date see Readme), gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.data;

import de.gematik.idp.crypto.model.PkiIdentity;
import java.util.Optional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@RequiredArgsConstructor
@Getter
@Setter
public class FederationPrivKey {

  private final PkiIdentity identity;
  private Optional<Boolean> addX5c;
  private String keyId;
  private Optional<String> use;

  public IdpKeyDescriptor buildJwk() {
    final IdpKeyDescriptor keyDesc =
        IdpKeyDescriptor.constructFromX509Certificate(
            identity.getCertificate(), keyId, addX5c.orElse(false));
    keyDesc.setPublicKeyUse(use.orElse(null));
    return keyDesc;
  }
}
