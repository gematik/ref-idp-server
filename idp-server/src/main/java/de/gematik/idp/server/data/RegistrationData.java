/*
 * Copyright (Change Date see Readme), gematik GmbH
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

package de.gematik.idp.server.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import de.gematik.idp.exceptions.IdpJoseException;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jose4j.json.internal.json_simple.JSONAware;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;
import tools.jackson.databind.json.JsonMapper;

@Data
@Builder
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
@AllArgsConstructor
@NoArgsConstructor
public class RegistrationData implements JSONAware, DataVersion {

  @NotNull private String signedPairingData;
  @NotNull private String authCert;
  @NotNull @Valid private DeviceInformation deviceInformation;
  @NotEmpty private String registrationDataVersion;

  @Override
  public String toJSONString() {
    try {
      final JsonMapper jsonMapper =
          JsonMapper.builder()
              .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false)
              .build();
      return jsonMapper.writeValueAsString(this);
    } catch (final JacksonException e) {
      throw new IdpJoseException("Error during Claim serialization", e);
    }
  }

  @Override
  @JsonIgnore
  public String getDataVersion() {
    return registrationDataVersion;
  }
}
