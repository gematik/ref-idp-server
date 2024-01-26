/*
 *  Copyright 2023 gematik GmbH
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
 */

package de.gematik.idp.server.controllers;

import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.IdpKeyDescriptor;
import java.util.Optional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@RequiredArgsConstructor
@Getter
public class IdpKey {

  private final PkiIdentity identity;

  @Setter private Optional<Boolean> addX5c;
  @Setter private Optional<String> keyId;
  @Setter private Optional<String> use;

  public IdpKeyDescriptor buildJwk() {
    final IdpKeyDescriptor keyDesc =
        IdpKeyDescriptor.constructFromX509Certificate(
            identity.getCertificate(), keyId.orElse("null"), addX5c.orElse(false));
    keyDesc.setPublicKeyUse(use.orElse(null));
    return keyDesc;
  }
}
