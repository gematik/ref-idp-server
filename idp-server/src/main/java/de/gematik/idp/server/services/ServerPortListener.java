/*
 *  Copyright 2024 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.server.services;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.context.WebServerInitializedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Getter
@Slf4j
@Component
public class ServerPortListener implements ApplicationListener<WebServerInitializedEvent> {

  private int serverPort = 0;

  @Override
  public void onApplicationEvent(final WebServerInitializedEvent event) {
    if (serverPort == 0) {
      this.serverPort = event.getWebServer().getPort();
      log.info("Server is running on port: {}", this.getServerPort());
    }
  }
}
