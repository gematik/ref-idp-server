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

import static de.gematik.idp.IdpConstants.PAIRING_ENDPOINT;

import de.gematik.idp.server.RequestAccessToken;
import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.data.PairingList;
import de.gematik.idp.server.services.PairingService;
import de.gematik.idp.server.validation.accessToken.ValidateAccessToken;
import de.gematik.idp.server.validation.clientSystem.ValidateClientSystem;
import de.gematik.idp.token.IdpJwe;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Transactional
@Valid
public class PairingController {

  private final PairingService pairingService;
  private final RequestAccessToken requestAccessToken;

  @GetMapping(value = PAIRING_ENDPOINT, produces = MediaType.APPLICATION_JSON_VALUE)
  @ValidateClientSystem
  @ValidateAccessToken
  public PairingList getAllPairingsForKvnr(final HttpServletResponse response) {
    setNoCacheHeader(response);
    return new PairingList(
        pairingService.validateTokenAndGetPairingList(requestAccessToken.getAccessToken()));
  }

  @DeleteMapping(
      value = {PAIRING_ENDPOINT, PAIRING_ENDPOINT + "/", PAIRING_ENDPOINT + "/{key_identifier}"})
  @ValidateAccessToken
  @ValidateClientSystem
  @ResponseStatus(value = HttpStatus.NO_CONTENT)
  public void deleteSinglePairing(
      final HttpServletResponse response,
      @PathVariable(value = "key_identifier") final String keyIdentifier) {
    setNoCacheHeader(response);
    pairingService.validateTokenAndDeleteSelectedPairing(
        requestAccessToken.getAccessToken(), keyIdentifier);
  }

  @PostMapping(
      value = PAIRING_ENDPOINT,
      consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @ValidateAccessToken
  @ValidateClientSystem
  public PairingDto insertPairing(
      final HttpServletResponse response,
      @RequestParam(value = "encrypted_registration_data", required = false) @NotNull
          final IdpJwe registrationData) {
    setNoCacheHeader(response);
    return pairingService.validatePairingData(
        requestAccessToken.getAccessToken(), registrationData);
  }

  private static void setNoCacheHeader(final HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Pragma", "no-cache");
  }
}
