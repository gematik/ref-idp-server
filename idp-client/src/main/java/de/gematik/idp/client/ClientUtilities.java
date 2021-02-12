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

package de.gematik.idp.client;

import java.security.PublicKey;
import java.util.Base64;
import java.util.Locale;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientUtilities {

    private static final String UPPER_CASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWER_CASE = UPPER_CASE.toLowerCase(Locale.ROOT);
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_SIGN = "-_.~";
    private static final String ALPHANUM = UPPER_CASE + LOWER_CASE + DIGITS + SPECIAL_SIGN;

    public static void verifyJwt(final String jwt, final PublicKey publicKey) {
        final JwtConsumer jwtConsumer = new JwtConsumerBuilder()
            .setVerificationKey(publicKey)
            .setSkipDefaultAudienceValidation()
            .build();

        try {
            jwtConsumer.process(jwt);
        } catch (final InvalidJwtException e) {
            throw new IdpClientRuntimeException(e);
        }
    }

    public static String generateCodeChallenge(final String codeVerifier) {
        // see https://tools.ietf.org/html/rfc7636#section-4.2
        return new String(Base64.getUrlEncoder().withoutPadding().encode(DigestUtils.sha256(codeVerifier)));
    }

    @SuppressWarnings("java:S2245")
    public static String generateCodeVerifier() {
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(DigestUtils.sha256(RandomStringUtils.random(123)));
    }
}
