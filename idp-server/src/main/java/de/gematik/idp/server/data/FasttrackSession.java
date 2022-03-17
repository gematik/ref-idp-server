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

package de.gematik.idp.server.data;

import static de.gematik.idp.field.ClaimName.*;
import java.util.HashMap;
import java.util.Map;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class FasttrackSession {

    // userAgent == e.g. eRezeptApp, outer session related artifacts
    private final String userAgentCodeChallenge;
    private final String userAgentCodeChallengeMethod;
    private final String userAgentNonce;
    private final String userAgentState;
    private final String userAgentId;
    private final String userAgentSekIdp;
    private final String userAgentRedirektUri;
    private final String userResponseType;


    // IDP-Server, inner session related artifacts
    private final String idpCodeVerifier;

    public Map<String, String> getSessionDataAsMap() {
        final Map<String, String> sessionMap = new HashMap<>();
        sessionMap.put(CODE_CHALLENGE.getJoseName(), userAgentCodeChallenge);
        sessionMap.put(CODE_CHALLENGE_METHOD.getJoseName(), userAgentCodeChallengeMethod);
        sessionMap.put(NONCE.getJoseName(), userAgentNonce);
        sessionMap.put(STATE.getJoseName(), userAgentState);
        sessionMap.put(REDIRECT_URI.getJoseName(), userAgentRedirektUri);
        sessionMap.put(CLIENT_ID.getJoseName(), userAgentId);
        sessionMap.put(RESPONSE_TYPE.getJoseName(), userResponseType);

        return sessionMap;
    }
}
