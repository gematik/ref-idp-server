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

package de.gematik.idp.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.client.data.DeviceInformation;
import de.gematik.idp.client.data.DeviceType;
import de.gematik.idp.client.data.DiscoveryDocumentResponse;
import de.gematik.idp.client.data.RegistrationData;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.field.ClaimName;
import de.gematik.idp.token.IdpJwe;
import de.gematik.idp.token.JsonWebToken;
import jakarta.ws.rs.core.HttpHeaders;
import java.security.KeyPair;
import java.util.Base64;
import java.util.List;
import kong.unirest.GenericType;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import lombok.Builder;
import lombok.Data;
import lombok.SneakyThrows;
import org.apache.http.HttpStatus;
import org.springframework.http.MediaType;

@Builder
@Data
public class BiometrieClient {

  private static final String USER_AGENT = "IdP-Client";
  private static final String BEARER = "Bearer ";
  private final DiscoveryDocumentResponse discoveryDocumentResponse;
  private JsonWebToken accessToken;

  @SneakyThrows
  public RegistrationData insertPairing(
      final PkiIdentity identity, final KeyPair keyPairToRegister) {
    final JsonWebToken signedPairingData =
        new JwtBuilder()
            .setSignerKey(identity.getPrivateKey())
            .addBodyClaim(
                ClaimName.AUTH_CERT_SUBJECT_PUBLIC_KEY_INFO,
                Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(identity.getCertificate().getPublicKey().getEncoded()))
            .addBodyClaim(ClaimName.DEVICE_PRODUCT, "meinPhone")
            .addBodyClaim(
                ClaimName.CERTIFICATE_SERIALNUMBER,
                identity.getCertificate().getSerialNumber().toString())
            .addBodyClaim(ClaimName.KEY_IDENTIFIER, "seIdVomPhoneHerGeneriert")
            .addBodyClaim(
                ClaimName.SE_SUBJECT_PUBLIC_KEY_INFO,
                Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(keyPairToRegister.getPublic().getEncoded()))
            .addBodyClaim(
                ClaimName.CERTIFICATE_ISSUER,
                Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(
                        identity.getCertificate().getIssuerX500Principal().getEncoded()))
            .addBodyClaim(ClaimName.PAIRING_DATA_VERSION, "1.0")
            .addBodyClaim(
                ClaimName.CERTIFICATE_NOT_AFTER,
                identity.getCertificate().getNotAfter().toInstant().getEpochSecond())
            .buildJwt();
    return insertPairing(
        RegistrationData.builder()
            .authCert(
                Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(identity.getCertificate().getEncoded()))
            .signedPairingData(signedPairingData.getRawString())
            .deviceInformation(
                DeviceInformation.builder().deviceType(DeviceType.builder().build()).build())
            .build());
  }

  public RegistrationData insertPairing(final RegistrationData biometrieData) {
    try {
      final String payload =
          new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(biometrieData);
      final HttpResponse<String> response =
          Unirest.post(getPairingEndpoint())
              .field(
                  "encrypted_registration_data",
                  IdpJwe.createWithPayloadAndEncryptWithKey(
                          payload, discoveryDocumentResponse.getIdpEnc(), "JSON")
                      .getRawString())
              .header(HttpHeaders.AUTHORIZATION, buildAuthorizationHeader())
              .header(HttpHeaders.USER_AGENT, USER_AGENT)
              .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE)
              .asString();
      if (!response.isSuccess()) {
        throw new IdpClientRuntimeException("Error during registration: " + response.getBody());
      }
      return biometrieData;
    } catch (final JsonProcessingException e) {
      throw new IdpClientRuntimeException(e);
    }
  }

  private String buildAuthorizationHeader() {
    return BEARER + accessToken.encryptAsNjwt(discoveryDocumentResponse.getIdpEnc()).getRawString();
  }

  private String getPairingEndpoint() {
    return discoveryDocumentResponse.getPairingEndpoint();
  }

  public List<RegistrationData> getAllPairings() {
    final HttpResponse<List<RegistrationData>> response =
        Unirest.get(getPairingEndpoint())
            .header(HttpHeaders.AUTHORIZATION, buildAuthorizationHeader())
            .header(HttpHeaders.USER_AGENT, USER_AGENT)
            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .asObject(new GenericType<>() {});

    if (response.getStatus() != HttpStatus.SC_OK) {
      throw new IdpClientRuntimeException("Unexpected Server-Response " + response.getStatus());
    }

    return response.getBody();
  }

  public boolean deleteAllPairingsForKvnr(final String kvnr) {
    final HttpResponse<String> response =
        Unirest.delete(getPairingEndpoint() + "/" + kvnr)
            .header(HttpHeaders.AUTHORIZATION, BEARER + accessToken.getRawString())
            .header(HttpHeaders.USER_AGENT, USER_AGENT)
            .header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
            .asString();
    return response.getStatus() == HttpStatus.SC_OK;
  }
}
