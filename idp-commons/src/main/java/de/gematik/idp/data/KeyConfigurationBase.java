/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.idp.data;

import de.gematik.idp.crypto.model.PkiIdentity;
import java.util.Optional;

public interface KeyConfigurationBase {

  default FederationPrivKey getFederationPrivKey(
      final KeyConfig keyConfiguration, final PkiIdentity pkiIdentity) {
    final FederationPrivKey federationPrivKey = new FederationPrivKey(pkiIdentity);
    federationPrivKey.setKeyId(Optional.ofNullable(keyConfiguration.getKeyId()));
    federationPrivKey.setUse(Optional.ofNullable(keyConfiguration.getUse()));
    federationPrivKey.setAddX5c(Optional.of(keyConfiguration.isX5cInJwks()));
    return federationPrivKey;
  }
}
