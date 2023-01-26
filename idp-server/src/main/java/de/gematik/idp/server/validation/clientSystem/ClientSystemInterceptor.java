/*
 * Copyright (c) 2023 gematik GmbH
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

package de.gematik.idp.server.validation.clientSystem;

import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerClientSystemBlockedException;
import de.gematik.idp.server.exceptions.oauth2spec.IdpServerClientSystemMissingException;
import jakarta.ws.rs.core.HttpHeaders;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
@Slf4j
public class ClientSystemInterceptor implements HandlerInterceptor, WebMvcConfigurer {

  private final IdpConfiguration idpConfiguration;

  @Override
  public void addInterceptors(final InterceptorRegistry registry) {
    registry.addInterceptor(this).addPathPatterns("/**");
  }

  @Override
  public boolean preHandle(
      final jakarta.servlet.http.HttpServletRequest request,
      final jakarta.servlet.http.HttpServletResponse response,
      final Object handler) {
    if (!doesTargetMethodHaveValidationAnnotation(handler)) {
      return true;
    }

    final String clientSystem = request.getHeader(HttpHeaders.USER_AGENT);

    if (StringUtils.isEmpty(clientSystem)) {
      throw new IdpServerClientSystemMissingException();
    }

    if (idpConfiguration.getBlockedClientSystems().contains(clientSystem)) {
      throw new IdpServerClientSystemBlockedException();
    }

    return true;
  }

  private boolean doesTargetMethodHaveValidationAnnotation(final Object handler) {
    return Optional.ofNullable(handler)
        .filter(HandlerMethod.class::isInstance)
        .map(HandlerMethod.class::cast)
        .filter(handlerMethod -> handlerMethod.hasMethodAnnotation(ValidateClientSystem.class))
        .map(handlerMethod -> handlerMethod.getMethodAnnotation(ValidateClientSystem.class))
        .isPresent();
  }
}
