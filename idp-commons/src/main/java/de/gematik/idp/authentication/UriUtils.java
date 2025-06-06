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

package de.gematik.idp.authentication;

import de.gematik.idp.exceptions.IdpRuntimeException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
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

  public static String extractBaseUri(final String uriStr) {
    final URI uri;
    try {
      uri = new URI(uriStr);
    } catch (final URISyntaxException e) {
      throw new IdpRuntimeException(e);
    }

    return uri.getScheme() + "://" + uri.getHost() + uri.getPath();
  }

  public static boolean isValidUrl(final String url) {
    try {
      final URL ignored = URI.create(url).toURL();
      return true;
    } catch (final MalformedURLException | IllegalArgumentException e) {
      return false;
    }
  }
}
