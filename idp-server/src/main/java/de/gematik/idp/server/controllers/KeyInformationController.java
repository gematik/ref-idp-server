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

package de.gematik.idp.server.controllers;

import de.gematik.idp.data.IdpKeyDescriptor;
import de.gematik.idp.server.validation.clientSystem.ValidateClientSystem;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class KeyInformationController {

  public static final String PUK_URI_SIG = "/idpSig/jwk.json";
  public static final String PUK_URI_ENC = "/idpEnc/jwk.json";
  private final IdpKey idpEnc;
  private final IdpKey idpSig;

  @GetMapping(PUK_URI_SIG)
  @ValidateClientSystem
  public IdpKeyDescriptor getAuthJwk() {
    return idpSig.buildJwk(true);
  }

  @GetMapping(PUK_URI_ENC)
  @ValidateClientSystem
  public IdpKeyDescriptor getTokenJwk() {
    return idpEnc.buildJwk(false);
  }
}
