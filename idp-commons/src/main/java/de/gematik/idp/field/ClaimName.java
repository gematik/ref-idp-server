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

package de.gematik.idp.field;

import com.fasterxml.jackson.annotation.JsonValue;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum ClaimName {
  GIVEN_NAME("given_name"),
  FAMILY_NAME("family_name"),
  ORGANIZATION_NAME("organizationName"),
  PROFESSION_OID("professionOID"),
  ID_NUMBER("idNummer"),
  BIRTHDATE("birthdate"),
  TELEMATIK_ALTER("urn:telematik:claims:alter"),
  TELEMATIK_DISPLAY_NAME("urn:telematik:claims:display_name"),
  TELEMATIK_GIVEN_NAME("urn:telematik:claims:given_name"),
  TELEMATIK_GESCHLECHT("urn:telematik:claims:geschlecht"),
  TELEMATIK_EMAIL("urn:telematik:claims:email"),
  TELEMATIK_PROFESSION("urn:telematik:claims:profession"),
  TELEMATIK_ID("urn:telematik:claims:id"),
  TELEMATIK_ORGANIZATION("urn:telematik:claims:organization"),
  ISSUED_AT("iat"),
  AUTH_TIME("auth_time"),
  ISSUER("iss"),
  EXPIRES_AT("exp"),
  ALGORITHM("alg"),
  RESPONSE_TYPE("response_type"),
  SCOPE("scope"),
  CLIENT_ID("client_id"),
  STATE("state"),
  REDIRECT_URI("redirect_uri"),
  TYPE("typ"),
  CONTENT_TYPE("cty"),
  JWT_ID("jti"),
  KEY_ID("kid"),
  CLIENT_SIGNATURE("csig"),
  NESTED_JWT("njwt"),
  CODE_CHALLENGE("code_challenge"), // (Hashwert des "code_verifier") [RFC7636 # section-4.2]
  CODE_CHALLENGE_METHOD("code_challenge_method"), // HASH-Algorithmus (S256) [RFC7636 # section-4.3]
  CODE_VERIFIER("code_verifier"),
  CONFIRMATION("cnf"), // gemSpec_IDP_Dienst
  CLAIMS("claims"), // gemSpec_IDP_Dienst
  AUTHENTICATION_CLASS_REFERENCE(
      "acr"), // https://openid.net/specs/openid-connect-core-1_0.html#IDToken
  AUTHORIZED_PARTY("azp"),
  SUBJECT("sub"),
  X509_CERTIFICATE_CHAIN("x5c"),
  SERVER_NONCE("snc"),
  AUDIENCE("aud"),
  JWKS_URI("jwks_uri"),
  ACR_VALUES_SUPPORTED("acr_values_supported"),
  TOKEN_TYPE("token_type"),
  TOKEN_KEY("token_key"),
  NONCE("nonce"),
  ACCESS_TOKEN_HASH("at_hash"),
  AUTHENTICATION_DATA("authentication_data"),
  AUTHENTICATION_DATA_VERSION("authentication_data_version"),
  AUTHENTICATION_METHODS_REFERENCE("amr"),
  AUTHENTICATION_CERTIFICATE("auth_cert"),
  AUTH_CERT_SUBJECT_PUBLIC_KEY_INFO("auth_cert_subject_public_key_info"),
  SE_SUBJECT_PUBLIC_KEY_INFO("se_subject_public_key_info"),
  KEY_IDENTIFIER("key_identifier"),
  CHALLENGE_TOKEN("challenge_token"),
  DEVICE_INFORMATION("device_information"),
  DEVICE_NAME("name"),
  DEVICE_TYPE("device_type"),
  DEVICE_MANUFACTURER("manufacturer"),
  DEVICE_PRODUCT("product"),
  DEVICE_MODEL("model"),
  DEVICE_OS("os"),
  DEVICE_OS_VERSION("version"),
  SIGNED_PAIRING_DATA("signed_pairing_data"),
  PAIRING_DATA_VERSION("pairing_data_version"),
  PAIRING_DATA("pairing_data"),
  AUTHORITY_INFO_ACCESS("authority_info_access"),
  ENCRYPTION_ALGORITHM("enc"),
  CERTIFICATE_SERIALNUMBER("serialnumber"),
  CERTIFICATE_ISSUER("issuer"),
  CERTIFICATE_NOT_AFTER("not_after"),
  SIGNATURE_ALGORITHM_IDENTIFIER("signature_algorithm_identifier"),
  AUTHORIZATION_ENDPOINT("authorization_endpoint"),
  TOKEN_ENDPOINT("token_endpoint"),
  SSO_ENDPOINT("sso_endpoint"),
  URI_PAIR("uri_pair"),
  AUTH_PAIR_ENDPOINT("auth_pair_endpoint"),
  URI_PUK_IDP_SIG("uri_puk_idp_sig"),
  URI_PUK_IDP_ENC("uri_puk_idp_enc"),
  EPHEMERAL_PUBLIC_KEY("epk"),
  USE("use");

  @JsonValue private final String joseName;
}
