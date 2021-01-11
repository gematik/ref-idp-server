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

package de.gematik.idp.authentication;

import static de.gematik.idp.authentication.UriUtils.extractParameterValue;
import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class UriUtilsTest {

    @Test
    public void extractParameterValueSingle() {
        final String uri = "https://example.org/?a=1";
        assertThat(extractParameterValue(uri, "a")).isEqualTo("1");
    }

    @Test
    public void extractParameterValueSeveral() {
        final String uri = "https://example.org/?a=1&b=2&c=3";
        assertThat(extractParameterValue(uri, "a")).isEqualTo("1");
        assertThat(extractParameterValue(uri, "b")).isEqualTo("2");
        assertThat(extractParameterValue(uri, "c")).isEqualTo("3");
    }

    @Test
    public void extractParameterValueEncoding() {
        final String uri = "https://build.top.local/sonar/dashboard?id=de.gematik.idp%3Aidp-global";
        assertThat(extractParameterValue(uri, "id")).isEqualTo("de.gematik.idp:idp-global");
    }
}
