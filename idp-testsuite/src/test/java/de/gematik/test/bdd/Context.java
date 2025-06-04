/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.test.bdd;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.test.steps.model.DiscoveryDocument;
import io.restassured.response.Response;
import org.json.JSONObject;

public class Context extends ThreadedContextProvider {

  private static final Context SINGLETON = new Context();

  public static Context get() {
    return SINGLETON;
  }

  public static Response getCurrentResponse() {
    assertThat(get().get(ContextKey.RESPONSE))
        .withFailMessage("No Response in context!")
        .isNotNull();
    return (Response) get().get(ContextKey.RESPONSE);
  }

  public static JSONObject getCurrentClaims() {
    assertThat(get().get(ContextKey.CLAIMS)).withFailMessage("No Claims in context!").isNotNull();
    return (JSONObject) get().get(ContextKey.CLAIMS);
  }

  public static DiscoveryDocument getDiscoveryDocument() {
    assertThat(get().get(ContextKey.DISC_DOC))
        .withFailMessage("No Discovery Document in context!")
        .isNotNull();
    return (DiscoveryDocument) (get().get(ContextKey.DISC_DOC));
  }
}
