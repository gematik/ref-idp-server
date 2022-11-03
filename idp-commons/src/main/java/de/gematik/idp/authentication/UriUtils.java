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

package de.gematik.idp.authentication;

import de.gematik.idp.exceptions.IdpRuntimeException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class UriUtils {

  public static Optional<String> extractParameterValueOptional(
      final String uri, final String parameterName) {
    try {
      return Stream.of(new URI(uri).getQuery().split("&"))
          .filter(str -> str.startsWith(parameterName + "="))
          .map(str -> str.replace(parameterName + "=", ""))
          .findAny();
    } catch (final URISyntaxException e) {
      throw new IdpRuntimeException(e);
    }
  }

  public static Map<String, String> extractParameterMap(final String uri) {
    try {
      return Stream.of(new URI(uri).getQuery().split("&"))
          .filter(param -> param.contains("="))
          .map(param -> param.split("="))
          .collect(Collectors.toMap(array -> array[0], array -> array[1]));
    } catch (final URISyntaxException e) {
      throw new IdpRuntimeException(e);
    }
  }

  public static String extractParameterValue(final String uri, final String param) {
    return extractParameterValueOptional(uri, param)
        .orElseThrow(
            () ->
                new RuntimeException("Could not find '" + param + "' parameter in '" + uri + "'"));
  }
}
