/*
 * Copyright (c) 2020 gematik GmbH
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

package de.gematik.idp.server.data;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ApiModel(description = "Antwort des Gematik IDP Servers auf Tokenanfragen via getTokens().")
@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)
public class TokenResponse {
    @ApiModelProperty(notes = "Ablaufzeit der Gültigkeit der Tokens in Sekunden(?) TODO")
    private int expiresIn;
    // TODO what do we need this for?
    private String tokenType;
    @ApiModelProperty(notes = "ID Token TODO Abzuklären ob wir in unserer Umgebung ID Tokens verwenden.")
    private String idToken;
    @ApiModelProperty(notes = "Zugangstoken für den Zugriff auf Fachdienstdaten")
    private String accessToken;
    @ApiModelProperty(notes = "SingleSignOn Token für wiederholte Anfragen für einen Zugangstoken")
    private String ssoToken;
}
