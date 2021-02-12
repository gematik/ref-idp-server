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

package de.gematik.idp.server.services;

import de.gematik.idp.server.exceptions.oauth2spec.IdpPkceVerificationFailureException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerInvalidGrantException;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class PkceChecker {

    public static final Logger LOGGER = LoggerFactory.getLogger(PkceChecker.class);
    public static final Pattern VALID_CODE_VERIFIER_PATTERN = Pattern.compile("^[0-9a-zA-Z\\-\\.~_]+$");
    public static final int PKCE_CODE_VERIFIER_MIN_LENGTH = 43;
    public static final int PKCE_CODE_VERIFIER_MAX_LENGTH = 128;

    public void checkCodeVerifier(final String codeVerifier, final String codeChallenge) {
        if (StringUtils.isBlank(codeVerifier)) {
            throw new IdpServerInvalidGrantException("PKCE code verifier not specified");
        }
        verifyCodeVerifier(codeVerifier, codeChallenge);
    }

    private void verifyCodeVerifier(final String codeVerifier, final String codeChallenge) {
        if (!isValidPkceCodeVerifier(codeVerifier)) {
            throw new IdpPkceVerificationFailureException("Invalid PKCE: '" + codeVerifier + "'");
        }

        final String generatedCodeChallenge = generateCodeChallenge(codeVerifier);

        if (!codeChallenge.equals(generatedCodeChallenge)) {
            LOGGER.info("Failed PKCE validation: codeVerifier={}, generatedCodeChallenge={}, codeChallenge={}",
                codeVerifier, generatedCodeChallenge, codeChallenge);
            throw new IdpPkceVerificationFailureException("Failed PKCE validation");
        } else {
            LOGGER.debug("PKCE verification success. codeVerifierEncoded = {} codeChallenge = {}",
                generatedCodeChallenge,
                codeChallenge);
        }
    }

    private boolean isValidPkceCodeVerifier(final String codeVerifier) {
        if (codeVerifier.length() < PKCE_CODE_VERIFIER_MIN_LENGTH) {
            LOGGER.info("Error: PKCE codeVerifier length under lower limit , codeVerifier = '{}'", codeVerifier);
            return false;
        }
        if (codeVerifier.length() > PKCE_CODE_VERIFIER_MAX_LENGTH) {
            LOGGER.info("Error: PKCE codeVerifier length over upper limit , codeVerifier = '{}'", codeVerifier);
            return false;
        }
        final Matcher m = VALID_CODE_VERIFIER_PATTERN.matcher(codeVerifier);
        final boolean matchResult = m.matches();
        if (!matchResult) {
            LOGGER.info("Error: PKCE codeVerifier not match to pattern {}, codeVerifier = '{}'",
                VALID_CODE_VERIFIER_PATTERN, codeVerifier);
        }
        return matchResult;
    }

    private String generateCodeChallenge(final String codeVerifier) {
        // see https://tools.ietf.org/html/rfc7636#section-4.2
        return new String(Base64.getUrlEncoder().withoutPadding().encode(DigestUtils.sha256(codeVerifier)));
    }
}
