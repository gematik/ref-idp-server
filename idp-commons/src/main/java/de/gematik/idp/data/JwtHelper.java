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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.exceptions.IdpRuntimeException;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.NonNull;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public final class JwtHelper {

  public static String signJson(
      final IdpJwtProcessor jwtProcessor,
      final ObjectMapper objectMapper,
      final Object object,
      final String typ) {
    try {
      return jwtProcessor
          .buildJws(
              objectMapper.writeValueAsString(object), Map.ofEntries(Map.entry("typ", typ)), false)
          .getRawString();
    } catch (final JsonProcessingException e) {
      throw new IdpRuntimeException("EntityStatement to json failed", e);
    }
  }

  public static String invalidateJsonSignature(final String jwsRawString) {
    final String invalidSignatureValue =
        "Is8Ag-3Z0DwWS7RXCSRDPy1_m3bZatBB12PFOmTa8cBw0WrzixE23VL6xFeBFAFowlez-QQKU_WRhyPkX18-wQ";
    final String[] splitJws = jwsRawString.split("\\.");
    splitJws[2] = invalidSignatureValue;
    return String.join(".", splitJws);
  }

  public static IdpJwksDocument getJwks(final FederationPrivKey... federationPrivKeys) {
    return IdpJwksDocument.builder()
        .keys(
            Arrays.stream(federationPrivKeys)
                .map(
                    federationPrivKey -> {
                      final IdpKeyDescriptor keyDesc =
                          IdpKeyDescriptor.constructFromX509Certificate(
                              federationPrivKey.getIdentity().getCertificate(),
                              federationPrivKey.getKeyId(),
                              federationPrivKey.getAddX5c().orElse(false));
                      keyDesc.setPublicKeyUse(federationPrivKey.getUse().orElse(null));
                      return keyDesc;
                    })
                .toList())
        .build();
  }

  // TODO: IDP-740
  public static IdpJwksDocument getJwks(@NonNull final FederationPubKey... federationPubKeys) {
    return IdpJwksDocument.builder()
        .keys(
            Stream.of(federationPubKeys)
                .map(
                    federationPubKey -> {
                      final IdpKeyDescriptor keyDesc =
                          IdpKeyDescriptor.constructFromX509Certificate(
                              federationPubKey.getIdentity().getCertificate(),
                              federationPubKey.getKeyId(),
                              federationPubKey.getAddX5c().orElse(false));
                      keyDesc.setPublicKeyUse(federationPubKey.getUse().orElse(null));
                      return keyDesc;
                    })
                .toList())
        .build();
  }
}
