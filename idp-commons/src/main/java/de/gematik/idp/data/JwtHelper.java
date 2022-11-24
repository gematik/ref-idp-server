/*
 * Copyright (c) 2022 gematik GmbH
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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.exceptions.IdpRuntimeException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JwtHelper {

  public static String signJson(
      final IdpJwtProcessor jwtProcessor,
      final ObjectMapper objectMapper,
      final Object object,
      String typ) {
    try {
      return jwtProcessor
          .buildJws(
              objectMapper.writeValueAsString(object), Map.ofEntries(Map.entry("typ", typ)), false)
          .getRawString();
    } catch (final JsonProcessingException e) {
      throw new IdpRuntimeException("EntityStatement to json failed", e);
    }
  }

  public static IdpJwksDocument getJwks(final FederationPrivKey federationKey) {
    final List<PkiIdentity> identities = new ArrayList<>();
    identities.add(federationKey.getIdentity());
    return IdpJwksDocument.builder()
        .keys(
            identities.stream()
                .map(
                    identity -> {
                      final IdpKeyDescriptor keyDesc =
                          IdpKeyDescriptor.constructFromX509Certificate(
                              identity.getCertificate(), identity.getKeyId(), false);
                      keyDesc.setPublicKeyUse(identity.getUse().orElse(null));
                      return keyDesc;
                    })
                .collect(Collectors.toList()))
        .build();
  }

  // TODO: IDP-740
  public static IdpJwksDocument getJwks(@NonNull final FederationPubKey federationPubKey) {
    final List<PkiIdentity> identities = new ArrayList<>();
    identities.add(federationPubKey.getIdentity());
    return IdpJwksDocument.builder()
        .keys(
            identities.stream()
                .map(
                    identity -> {
                      final IdpKeyDescriptor keyDesc =
                          IdpKeyDescriptor.constructFromX509Certificate(
                              identity.getCertificate(), identity.getKeyId(), false);
                      keyDesc.setPublicKeyUse(identity.getUse().orElse(null));
                      return keyDesc;
                    })
                .collect(Collectors.toList()))
        .build();
  }
}
