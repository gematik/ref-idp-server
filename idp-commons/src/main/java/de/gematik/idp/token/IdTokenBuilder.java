/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.idp.token;

import static de.gematik.idp.IdpConstants.EIDAS_LOA_HIGH;
import static de.gematik.idp.IdpConstants.EREZEPT;
import static de.gematik.idp.field.ClaimName.ACCESS_TOKEN_HASH;
import static de.gematik.idp.field.ClaimName.AUDIENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_CLASS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTHENTICATION_METHODS_REFERENCE;
import static de.gematik.idp.field.ClaimName.AUTHORIZED_PARTY;
import static de.gematik.idp.field.ClaimName.AUTH_TIME;
import static de.gematik.idp.field.ClaimName.CLIENT_ID;
import static de.gematik.idp.field.ClaimName.DISPLAY_NAME;
import static de.gematik.idp.field.ClaimName.EXPIRES_AT;
import static de.gematik.idp.field.ClaimName.FAMILY_NAME;
import static de.gematik.idp.field.ClaimName.GIVEN_NAME;
import static de.gematik.idp.field.ClaimName.ID_NUMBER;
import static de.gematik.idp.field.ClaimName.ISSUED_AT;
import static de.gematik.idp.field.ClaimName.ISSUER;
import static de.gematik.idp.field.ClaimName.JWT_ID;
import static de.gematik.idp.field.ClaimName.NONCE;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_IK;
import static de.gematik.idp.field.ClaimName.ORGANIZATION_NAME;
import static de.gematik.idp.field.ClaimName.PROFESSION_OID;
import static de.gematik.idp.field.ClaimName.SUBJECT;
import static de.gematik.idp.field.ClaimName.TYPE;
import static de.gematik.idp.token.TokenBuilderUtil.addDisplayNameToBodyClaims;
import static de.gematik.idp.token.TokenBuilderUtil.buildSubjectClaim;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.Data;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.jose4j.jwt.NumericDate;

@Data
public class IdTokenBuilder {

  private static final List<ClaimName> CLAIMS_TO_TAKE_FROM_AUTHENTICATION_TOKEN =
      List.of(
          GIVEN_NAME,
          FAMILY_NAME,
          ORGANIZATION_NAME,
          PROFESSION_OID,
          ID_NUMBER,
          AUTH_TIME,
          NONCE,
          ORGANIZATION_IK);

  private final IdpJwtProcessor jwtProcessor;
  private final String issuerUrl;
  private final String serverSubjectSalt;

  public JsonWebToken buildIdToken(
      final String clientId,
      final JsonWebToken authenticationToken,
      final JsonWebToken accessToken) {
    final Map<String, Object> claimsMap = new HashMap<>();
    final ZonedDateTime now = ZonedDateTime.now();
    final String atHashValue =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(
                ArrayUtils.subarray(DigestUtils.sha256(accessToken.getRawString()), 0, 16));

    claimsMap.put(ISSUER.getJoseName(), issuerUrl);
    claimsMap.put(AUDIENCE.getJoseName(), clientId);
    claimsMap.put(ISSUED_AT.getJoseName(), now.toEpochSecond());

    CLAIMS_TO_TAKE_FROM_AUTHENTICATION_TOKEN.stream()
        .map(claimName -> Pair.of(claimName, authenticationToken.getBodyClaim(claimName)))
        .forEach(
            pair ->
                claimsMap.put(
                    pair.getKey().getJoseName(),
                    pair.getValue().isPresent() ? pair.getValue().get() : null));

    final Optional<Object> nonceInAuthCode = authenticationToken.getBodyClaim(NONCE);
    nonceInAuthCode.ifPresent(o -> claimsMap.put(NONCE.getJoseName(), o));
    // for erezept in federation
    if (authenticationToken.getScopesBodyClaim().contains(EREZEPT)) {
      final Optional<Object> displayName = authenticationToken.getBodyClaim(DISPLAY_NAME);
      addDisplayNameToBodyClaims(displayName, claimsMap);
    }
    claimsMap.put(
        AUTHORIZED_PARTY.getJoseName(),
        authenticationToken
            .getBodyClaim(CLIENT_ID)
            .orElseThrow(
                () ->
                    new IdpJoseException(
                        "Missing '" + AUTHORIZED_PARTY.getJoseName() + "' claim!")));
    claimsMap.put(
        AUTHENTICATION_METHODS_REFERENCE.getJoseName(),
        accessToken.getBodyClaim(AUTHENTICATION_METHODS_REFERENCE).orElseThrow());
    claimsMap.put(AUTHENTICATION_CLASS_REFERENCE.getJoseName(), EIDAS_LOA_HIGH);
    claimsMap.put(ACCESS_TOKEN_HASH.getJoseName(), atHashValue);
    claimsMap.put(
        SUBJECT.getJoseName(),
        buildSubjectClaim(
            clientId,
            authenticationToken
                .getStringBodyClaim(ID_NUMBER)
                .orElseThrow(
                    () -> new IdpJoseException("Missing '" + ID_NUMBER.getJoseName() + "' claim!")),
            serverSubjectSalt));
    claimsMap.put(JWT_ID.getJoseName(), Nonce.getNonceAsHex(IdpConstants.JTI_LENGTH));
    claimsMap.put(
        EXPIRES_AT.getJoseName(),
        NumericDate.fromSeconds(now.plusMinutes(5).toEpochSecond()).getValue());

    final Map<String, Object> headerClaims = new HashMap<>();
    headerClaims.put(TYPE.getJoseName(), "JWT");

    return jwtProcessor.buildJwt(
        new JwtBuilder().addAllBodyClaims(claimsMap).addAllHeaderClaims(headerClaims));
  }
}
