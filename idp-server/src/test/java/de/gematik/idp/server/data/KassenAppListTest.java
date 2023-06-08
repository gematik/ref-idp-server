/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.idp.server.data;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

class KassenAppListTest {

  @Test
  void checkMappingToJsonIsCorrect() throws JsonProcessingException {

    final ObjectMapper objectMapper = new ObjectMapper();
    final KassenAppList kassenAppList = new KassenAppList();

    kassenAppList.add(
        KkAppListEntry.builder()
            .kkAppId("id1")
            .kkAppName("Gematik KK")
            .kkAppUri("www.tk42.de")
            .build());

    kassenAppList.add(
        KkAppListEntry.builder()
            .kkAppId("id2")
            .kkAppName("meine krankenkasse")
            .kkAppUri("www.myKK.de")
            .build());

    assertThat(objectMapper.writeValueAsString(kassenAppList))
        .isEqualTo(
            "{\"kk_app_list\":[{\"kk_app_name\":\"Gematik"
                + " KK\",\"kk_app_id\":\"id1\"},{\"kk_app_name\":\"meine"
                + " krankenkasse\",\"kk_app_id\":\"id2\"}]}");
  }
}
