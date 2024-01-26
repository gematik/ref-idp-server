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

package de.gematik.idp.data;

import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@Setter
@AllArgsConstructor
@RequiredArgsConstructor
@Getter
public class FederationPubKey {

  private Optional<X509Certificate> certificate = Optional.empty();
  private Optional<PublicKey> publicKey = Optional.empty();
  private String keyId;
  private Optional<String> use = Optional.empty();

  public IdpKeyDescriptor buildJwkWithX5c() {
    return IdpKeyDescriptor.constructFromX509Certificate(certificate.orElseThrow(), keyId, true);
  }

  public IdpKeyDescriptor buildJwkWithoutX5c() {
    if (publicKey.isPresent()) {
      final IdpKeyDescriptor keyDesc = IdpKeyDescriptor.createFromPublicKey(publicKey.get(), keyId);
      use.ifPresent(keyDesc::setPublicKeyUse);
      return keyDesc;
    } else if (certificate.isPresent()) {
      final IdpKeyDescriptor keyDesc =
          IdpKeyDescriptor.constructFromX509Certificate(certificate.get(), keyId, false);
      use.ifPresent(keyDesc::setPublicKeyUse);
      return keyDesc;
    } else {
      throw new IdpCryptoException(
          "FederationPubKey invalid. No PublicKey or certificate present.");
    }
  }
}
