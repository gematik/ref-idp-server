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

    public Map<String, String> getSesstionDataAsMap() {
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
