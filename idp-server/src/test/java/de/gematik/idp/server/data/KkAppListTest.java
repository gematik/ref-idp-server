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

import static org.assertj.core.api.Assertions.assertThat;

import kong.unirest.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class KkAppListTest {

  @Test
  void getListAsJsonStringCheckMapToJson() {
    final KkAppList kkAppList = new KkAppList();

    kkAppList.add(
        KkAppListEntry.builder()
            .kkAppId("id1")
            .kkAppName("Gematik KK")
            .kkAppUri("www.tk42.de")
            .build());

    kkAppList.add(
        KkAppListEntry.builder()
            .kkAppId("id2")
            .kkAppName("meine krankenkasse")
            .kkAppUri("www.myKK.de")
            .build());

    System.out.println(kkAppList.getListAsJson());
    final JSONObject json = kkAppList.getListAsJson();
    assertThat(json.getJSONArray("kk_app_list").length()).isEqualTo(2);
  }
}
