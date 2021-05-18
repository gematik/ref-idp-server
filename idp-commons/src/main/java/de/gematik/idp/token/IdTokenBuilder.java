/*
 * Copyright (c) 2021 gematik GmbH
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

package de.gematik.idp.token;

import static de.gematik.idp.field.ClaimName.*;
import static de.gematik.idp.token.TokenBuilderUtil.buildSubjectClaim;

import java.time.ZonedDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.jose4j.jwt.NumericDate;

import de.gematik.idp.IdpConstants;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.authentication.JwtBuilder;
import de.gematik.idp.crypto.Nonce;
import de.gematik.idp.exceptions.IdpJoseException;
import de.gematik.idp.field.ClaimName;
import lombok.Data;

@Data
public class IdTokenBuilder {

    private static final Set<String> requiredClaims = Stream.of(PROFESSION_OID, GIVEN_NAME, FAMILY_NAME,
            ORGANIZATION_NAME, ID_NUMBER, AUTHENTICATION_CLASS_REFERENCE, CLIENT_ID, SCOPE, AUTH_TIME)
            .map(ClaimName::getJoseName)
            .collect(Collectors.toSet());
    private static final List<ClaimName> CLAIMS_TO_TAKE_FROM_AUTHENTICATION_TOKEN = List
            .of(GIVEN_NAME, FAMILY_NAME, ORGANIZATION_NAME, PROFESSION_OID, ID_NUMBER, AUTH_TIME, NONCE);

    private final IdpJwtProcessor jwtProcessor;
    private final String issuerUrl;
    private final String serverSubjectSalt;

    public JsonWebToken buildIdToken(final String clientId, final JsonWebToken authenticationToken,
            final byte[] accesTokenHash) {
        final Map<String, Object> claimsMap = new HashMap<>();
        final ZonedDateTime now = ZonedDateTime.now();
        final String atHashValue = Base64.getUrlEncoder().withoutPadding().encodeToString(
                ArrayUtils.subarray(accesTokenHash, 0, 16));

        claimsMap.put(ISSUER.getJoseName(), issuerUrl);
        claimsMap.put(SUBJECT.getJoseName(), clientId);
        claimsMap.put(AUDIENCE.getJoseName(), clientId);
        claimsMap.put(ISSUED_AT.getJoseName(), now.toEpochSecond());

        CLAIMS_TO_TAKE_FROM_AUTHENTICATION_TOKEN.stream()
                .map(claimName -> Pair.of(claimName, authenticationToken.getBodyClaim(claimName)))
                .filter(pair -> pair.getValue().isPresent())
                .forEach(pair -> claimsMap.put(pair.getKey().getJoseName(), pair.getValue().get()));
        claimsMap.put(AUTHORIZED_PARTY.getJoseName(),
                authenticationToken.getBodyClaim(CLIENT_ID)
                        .orElseThrow(() -> new IdpJoseException("Missing '" + AUTHORIZED_PARTY.getJoseName() + "' claim!")));
        claimsMap.put(AUTHENTICATION_METHODS_REFERENCE.getJoseName(), getAmrString());
        claimsMap.put(AUTHENTICATION_CLASS_REFERENCE.getJoseName(), IdpConstants.EIDAS_LOA_HIGH);
        claimsMap.put(ACCESS_TOKEN_HASH.getJoseName(), atHashValue);
        claimsMap.put(SUBJECT.getJoseName(),
                buildSubjectClaim(
                        clientId,
                        authenticationToken.getStringBodyClaim(ID_NUMBER)
                                .orElseThrow(() -> new IdpJoseException("Missing '" + ID_NUMBER.getJoseName() + "' claim!")),
                    serverSubjectSalt));
        claimsMap.put(JWT_ID.getJoseName(), new Nonce().getNonceAsHex(IdpConstants.JTI_LENGTH));
        claimsMap.put(EXPIRES_AT.getJoseName(), NumericDate.fromSeconds(now.plusMinutes(5).toEpochSecond()).getValue());

        final Map<String, Object> headerClaims = new HashMap<>();
        headerClaims.put(TYPE.getJoseName(), "JWT");

        return jwtProcessor.buildJwt(new JwtBuilder()
                .addAllBodyClaims(claimsMap)
                .addAllHeaderClaims(headerClaims));
    }

    private String[] getAmrString() {
        return new String[] { "mfa", "sc", "pin" };
    }
}
