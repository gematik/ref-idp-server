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

package de.gematik.idp.server;

import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.services.ServerVersionInterceptor;
import java.security.Security;
import java.util.Locale;
import javax.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import net.dracoblue.spring.web.mvc.method.annotation.HttpResponseHeaderHandlerInterceptor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.trace.http.HttpTraceRepository;
import org.springframework.boot.actuate.trace.http.InMemoryHttpTraceRepository;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.web.filter.CommonsRequestLoggingFilter;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;

@SpringBootApplication(scanBasePackages = {"de.gematik.idp", "net.dracoblue"})
@RequiredArgsConstructor
public class IdpServer implements WebMvcConfigurer {

  static {
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    Security.insertProviderAt(new BouncyCastleProvider(), 1);
  }

  private final IdpConfiguration idpConfiguration;
  private final HttpResponseHeaderHandlerInterceptor httpResponsHeaderHandlerInterceptor;
  private final ServerVersionInterceptor serverVersionInterceptor;

  @SuppressWarnings("java:S4823")
  public static void main(final String[] args) {
    SpringApplication.run(IdpServer.class, args);
  }

  @Bean
  @ConditionalOnProperty(value = "idp.debug.requestLogging")
  public CommonsRequestLoggingFilter requestLoggingFilter() {
    final CommonsRequestLoggingFilter loggingFilter = new CommonsRequestLoggingFilter();
    loggingFilter.setIncludeClientInfo(true);
    loggingFilter.setIncludeQueryString(true);
    loggingFilter.setIncludePayload(true);
    loggingFilter.setMaxPayloadLength(64000);
    return loggingFilter;
  }

  @PostConstruct
  public void setIdpLocale() {
    if (idpConfiguration.getDefaultLocale() != null) {
      Locale.setDefault(idpConfiguration.getDefaultLocale());
    }
  }

  @Bean
  public ResourceHttpRequestHandler resourceHttpRequestHandler() {
    return new ResourceHttpRequestHandler();
  }

  @Bean
  public WebMvcConfigurer headerConfigurer() {
    return new WebMvcConfigurer() {
      @Override
      public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(httpResponsHeaderHandlerInterceptor);
        registry.addInterceptor(serverVersionInterceptor);
      }
    };
  }

  @Bean
  public HttpTraceRepository httpTraceRepository() {
    return new InMemoryHttpTraceRepository();
  }
}
