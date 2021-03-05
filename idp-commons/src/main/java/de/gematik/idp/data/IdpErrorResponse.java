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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import de.gematik.idp.error.IdpErrorType;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder(toBuilder = true)
@AllArgsConstructor
@NoArgsConstructor
@ApiModel(description = "Antwort Objekt, wenn eine OAuth2 / OICD Exception geworfen wurde.")
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class IdpErrorResponse {

    @ApiModelProperty(notes = "Error code laut OAuth2 / OICD spec.")
    private IdpErrorType error;
    @ApiModelProperty(notes = "Detaillierter gematik Fehlercode, 4-stellig")
    @JsonProperty("gematik_code")
    private int code;
    @ApiModelProperty(notes = "Zeitpunkt des Fehlers in Sekunden seit 01.01.1970 UTC.")
    @JsonProperty("gematik_timestamp")
    private String timestamp;
    @ApiModelProperty(notes = "eindeutige, generierte uuid für den Fehler")
    @JsonProperty("gematik_uuid")
    private String errorUuid;
    @ApiModelProperty(notes = "Fehlertext für den Endbenutzer.")
    @JsonProperty("gematik_error_text")
    private String detailMessage;

}
