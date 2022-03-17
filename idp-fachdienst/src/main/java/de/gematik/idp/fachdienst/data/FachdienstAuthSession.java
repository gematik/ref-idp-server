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

package de.gematik.idp.fachdienst.data;

import static de.gematik.idp.field.ClaimName.*;
import java.util.HashMap;
import java.util.Map;
import lombok.Builder;
import lombok.Getter;

/**
 * Federation Authorization session fachdienstState is key to session, wird in Nachricht 7 des App2App flows vom
 * Idp-Sektoral an das Frontend versendet und kommt vom Frontend als Param von Nachricht 9 hierher zurück
 */
@Getter
@Builder
public class FachdienstAuthSession {

    // outer session related artifacts taken from app request
    private final String frontendClientId;
    // wird in Nachricht 12 des App2App flows versendet
    private final String frontendState;
    private final String frontendRedirektUri;
    private final String frontendCodeChallenge;
    private final String frontendCodeChallengeMethod;

    // IDP-Fachdienst, inner session related artifacts
    private final String fachdienstCodeverifier;

    public Map<String, String> getSessionDataAsMap() {
        final Map<String, String> sessionMap = new HashMap<>();
        sessionMap.put(CLIENT_ID.getJoseName(), frontendClientId);
        sessionMap.put(STATE.getJoseName(), frontendState);
        sessionMap.put(REDIRECT_URI.getJoseName(), frontendRedirektUri);
        sessionMap.put(CODE_CHALLENGE.getJoseName(), frontendCodeChallenge);
        sessionMap.put(CODE_CHALLENGE_METHOD.getJoseName(), frontendCodeChallengeMethod);
        return sessionMap;
    }
}
