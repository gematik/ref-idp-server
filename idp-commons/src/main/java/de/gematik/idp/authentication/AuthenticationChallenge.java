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

package de.gematik.idp.authentication;

import com.fasterxml.jackson.annotation.*;
import de.gematik.idp.data.*;
import de.gematik.idp.token.*;
import io.swagger.annotations.*;
import lombok.*;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@ApiModel("Antwort des Gematik IDP Servers auf Anfragen via getAuthenticationChallenge().")
public class AuthenticationChallenge {

    @ApiModelProperty(value = "Am IDP Server erzeugte Challenge")
    private JsonWebToken challenge;
    @JsonProperty(value = "user_consent")
    @ApiModelProperty(value = "Die vom Benutzer einzuholende Zustimmung.")
    private UserConsent userConsent;
}
