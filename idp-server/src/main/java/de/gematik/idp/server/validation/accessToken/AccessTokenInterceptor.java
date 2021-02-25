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

package de.gematik.idp.server.validation.accessToken;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.field.IdpScope;
import de.gematik.idp.server.RequestAccessToken;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerAccessDeniedException;
import de.gematik.idp.token.JsonWebToken;
import java.util.Optional;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.HttpHeaders;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Service
@RequiredArgsConstructor
@Slf4j
public class AccessTokenInterceptor implements HandlerInterceptor, WebMvcConfigurer {

    private final IdpJwtProcessor jwtProcessor;
    private final RequestAccessToken requestAccessToken;

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(this).addPathPatterns("/**");
    }

    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response,
        final Object handler) {
        if (!doesTargetMethodHaveValidationAnnotation(handler)) {
            return true;
        }

        final JsonWebToken accessToken = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
            .filter(StringUtils::isNotEmpty)
            .filter(authorizationHeader -> authorizationHeader.startsWith("Bearer "))
            .map(authorizationHeader -> authorizationHeader.split("Bearer ")[1])
            .map(token -> new JsonWebToken(token))
            .orElseThrow(() -> new IdpServerAccessDeniedException("No authorization-Header with Bearer-Token given"));

        try {
            jwtProcessor.verifyAndThrowExceptionIfFail(accessToken);
        } catch (final RuntimeException e) {
            throw new IdpServerAccessDeniedException("Error while verifying Access-Token");
        }

        if (!accessToken.getScopesBodyClaim().contains(IdpScope.PAIRING)) {
            throw new IdpServerAccessDeniedException("Scope missing: " + IdpScope.PAIRING.getJwtValue());
        }

        requestAccessToken.setAccessToken(accessToken);

        return true;
    }

    private boolean doesTargetMethodHaveValidationAnnotation(final Object handler) {
        return Optional.ofNullable(handler)
            .filter(HandlerMethod.class::isInstance)
            .map(HandlerMethod.class::cast)
            .filter(handlerMethod -> handlerMethod.hasMethodAnnotation(ValidateAccessToken.class))
            .map(handlerMethod -> handlerMethod.getMethodAnnotation(ValidateAccessToken.class))
            .isPresent();
    }
}
