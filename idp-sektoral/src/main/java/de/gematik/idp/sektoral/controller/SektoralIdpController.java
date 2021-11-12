package de.gematik.idp.sektoral.controller;

import static de.gematik.idp.IdpConstants.SEKTORAL_IDP_AUTHORIZATION_ENDPOINT;
import static de.gematik.idp.IdpConstants.TOKEN_ENDPOINT;
import de.gematik.idp.sektoral.data.TokenResponse;
import de.gematik.idp.sektoral.services.SektoralIdpAuthenticator;
import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Slf4j
public class SektoralIdpController {

    public static final String HARD_CODED_ID_TOKEN = "eyJhbGciOiJCUDI1NlIxIiwia2lkIjoicHVrX2lkcF9zaWciLCJ0eXAiOiJKV1QifQ.eyJhdXRoX3RpbWUiOjE2MjMwNTYxMzYsIm5vbmNlIjoiOTg3NjUiLCJnaXZlbl9uYW1lIjoiRGFyaXVzIE1pY2hhZWwgQnJpYW4gVWJibyIsImZhbWlseV9uYW1lIjoiQsO2ZGVmZWxkIiwib3JnYW5pemF0aW9uTmFtZSI6IlRlc3QgR0tWLVNWTk9ULVZBTElEIiwicHJvZmVzc2lvbk9JRCI6IjEuMi4yNzYuMC43Ni40LjQ5IiwiaWROdW1tZXIiOiJYMTEwNDExNjc1IiwiYXpwIjoiZVJlemVwdEFwcCIsImFjciI6ImdlbWF0aWstZWhlYWx0aC1sb2EtaGlnaCIsImFtciI6WyJtZmEiLCJzYyIsInBpbiJdLCJhdWQiOiJlUmV6ZXB0QXBwIiwic3ViIjoiOGMwN2UzNzYwZjM1NjE5YzJlNWNjY2JkMzQxMzU0NDcwYjgwMmU5ZGIyZTkyYTgzNjMwMzdlYjc5OTkwYjU2ZSIsImlzcyI6Imh0dHBzOi8vaWRwLXRlc3QuemVudHJhbC5pZHAuc3BsaXRkbnMudGktZGllbnN0ZS5kZSIsImlhdCI6MTYyMzA1NjEzNiwiZXhwIjoxNjIzMDk5MzM2LCJqdGkiOiJjNjRiZmU2YS1kNzUyLTRlNWYtODA5YS0zM2IzOGUwYzNlOGUiLCJhdF9oYXNoIjoicUc5QXU4ei1kNVE2MllJWXlBRV9rQSJ9.Z0mhWFS2TcUtZlj-KAX9ys9Az-MwEvQ6AxRMLh2mKSdG6PKfsxsXJQhldeIzD1s2zcTTe74QPd0xUG8OCz9VuQ";
    public static final String HARD_CODED_ACCESS_TOKEN = "eyJhbGciOiJCUDI1NlIxIiwia2lkIjoicHVrX2lkcF9zaWciLCJ0eXAiOiJhdCtKV1QifQ.eyJhdXRoX3RpbWUiOjE2MjMwNTYxMzYsInNjb3BlIjoib3BlbmlkIGUtcmV6ZXB0IiwiY2xpZW50X2lkIjoiZVJlemVwdEFwcCIsImdpdmVuX25hbWUiOiJEYXJpdXMgTWljaGFlbCBCcmlhbiBVYmJvIiwiZmFtaWx5X25hbWUiOiJCw7ZkZWZlbGQiLCJvcmdhbml6YXRpb25OYW1lIjoiVGVzdCBHS1YtU1ZOT1QtVkFMSUQiLCJwcm9mZXNzaW9uT0lEIjoiMS4yLjI3Ni4wLjc2LjQuNDkiLCJpZE51bW1lciI6IlgxMTA0MTE2NzUiLCJhenAiOiJlUmV6ZXB0QXBwIiwiYWNyIjoiZ2VtYXRpay1laGVhbHRoLWxvYS1oaWdoIiwiYW1yIjpbIm1mYSIsInNjIiwicGluIl0sImF1ZCI6Imh0dHBzOi8vZXJwLXRlc3QuemVudHJhbC5lcnAuc3BsaXRkbnMudGktZGllbnN0ZS5kZS8iLCJzdWIiOiI4YzA3ZTM3NjBmMzU2MTljMmU1Y2NjYmQzNDEzNTQ0NzBiODAyZTlkYjJlOTJhODM2MzAzN2ViNzk5OTBiNTZlIiwiaXNzIjoiaHR0cHM6Ly9pZHAtdGVzdC56ZW50cmFsLmlkcC5zcGxpdGRucy50aS1kaWVuc3RlLmRlIiwiaWF0IjoxNjIzMDU2MTM2LCJleHAiOjE2MjMwNTY0MzYsImp0aSI6IjAxNGI5YTI5LWExODEtNDRjNy05MTQ3LTUzZTcyMmQ3YzNkMSJ9.oLe-B87aFAHhX02d6ptFF_w-1LJEsCuEEWf72t7UpuYcI1F5GCsxf2HXnTz2TMbOOXa6GO9TlpT1OHSyQBTmEQ";
    private final SektoralIdpAuthenticator sektoralIdpAuthenticator;

    /* Fasttrack
     * Request(in)  == message nr.4
     *                 messages nr.5 and 6 are not part of this implementation
     * Response(out)== message nr.7
     */
    @GetMapping(value = SEKTORAL_IDP_AUTHORIZATION_ENDPOINT)
    public void getTokenCode(
        @RequestParam(name = "client_id") @NotEmpty(message = "1002") final String clientId,
        @RequestParam(name = "state") @NotEmpty(message = "2002") @Pattern(regexp = ".+", message = "2006") final String idpState,
        @RequestParam(name = "redirect_uri") @NotNull(message = "1004") final String redirectUri,
        @RequestParam(name = "nonce", required = false) @Pattern(regexp = ".+", message = "2007") final String nonce,
        @RequestParam(name = "response_type") @NotEmpty(message = "2004") @Pattern(regexp = "code", message = "2005") final String responseType,
        @RequestParam(name = "scope") final String scope,
        @RequestParam(name = "code_challenge") @NotEmpty(message = "2009") final String userAgentCodeChallenge,
        @RequestParam(name = "code_challenge_method") @Pattern(regexp = "S256", message = "2008") final String userAgentCodeChallengeMethod,
        final HttpServletResponse response) {
        log.info(
            "RequestParams (just used for Sonar: " + clientId + " " + idpState + " " + redirectUri + " " + nonce + " "
                + responseType + " " + scope + " " + userAgentCodeChallenge + " " + userAgentCodeChallengeMethod);
        setNoCacheHeader(response);
        response.setStatus(HttpStatus.FOUND.value());

        final String tokenLocation = sektoralIdpAuthenticator.createLocationForAuthorizationResponse(redirectUri, idpState);
        response.setHeader(HttpHeaders.LOCATION, tokenLocation);
    }

    /* Fasttrack
     * Request(in)  == message nr.10
     * Response(out)== message nr.11
     */
    @PostMapping(value = TOKEN_ENDPOINT, consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public TokenResponse getTokensForCode(
        @RequestParam(name = "client_id") @NotEmpty(message = "1002") final String clientId,
        @RequestParam("code") @NotNull(message = "3005") final String authenticationToken,
        @RequestParam("code_verifier") @NotNull final String code_verifier,
        @RequestParam("grant_type") @NotEmpty(message = "3006") @Pattern(regexp = "authorization_code", message = "3014") final String grantType,
        @RequestParam("redirect_uri") final String redirectUri,
        final HttpServletResponse response) {
        setNoCacheHeader(response);
        response.setStatus(HttpStatus.OK.value());
        return TokenResponse.builder().idToken(
                HARD_CODED_ID_TOKEN)
            .accessToken(
                HARD_CODED_ACCESS_TOKEN)
            .tokenType("Bearer").expiresIn(300).build();
    }

    private static void setNoCacheHeader(final HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
    }

}
