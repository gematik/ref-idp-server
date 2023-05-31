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

package de.gematik.idp.tests;

import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.exceptions.IdpCryptoException;
import de.gematik.idp.crypto.model.PkiIdentity;
import java.io.IOException;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterContext;
import org.junit.jupiter.api.extension.ParameterResolver;

public class PkiKeyResolver implements ParameterResolver {

  @Override
  public boolean supportsParameter(
      final ParameterContext parameterContext, final ExtensionContext extensionContext) {
    return parameterContext.getParameter().getType() == PkiIdentity.class;
  }

  @Override
  public PkiIdentity resolveParameter(
      final ParameterContext parameterContext, final ExtensionContext extensionContext) {
    return retrieveIdentityFromFileSystem(getFilterValueForParameter(parameterContext));
  }

  private String getFilterValueForParameter(final ParameterContext parameterContext) {
    if (parameterContext.getParameter().isAnnotationPresent(Filename.class)) {
      return parameterContext.getParameter().getAnnotation(Filename.class).value();
    } else {
      return parameterContext.getParameter().getName();
    }
  }

  private PkiIdentity retrieveIdentityFromFileSystem(final String fileFilter) {
    try (final Stream<Path> pathStream =
        Files.find(
            Paths.get("src", "test", "resources"),
            128,
            (p, a) ->
                p.toString().endsWith(".p12")
                    && p.getFileName()
                        .toString()
                        .toLowerCase()
                        .contains(fileFilter.toLowerCase()))) {
      return pathStream
          .findFirst()
          .map(Path::toFile)
          .map(
              file -> {
                try {
                  return FileUtils.readFileToByteArray(file);
                } catch (final IOException e) {
                  throw new IdpCryptoException(e);
                }
              })
          .map(bytes -> CryptoLoader.getIdentityFromP12(bytes, "00"))
          .orElseThrow(
              () ->
                  new IdpCryptoException(
                      "No matching identity found in src/test/resources and filter '"
                          + fileFilter
                          + "'"));
    } catch (final IOException e) {
      throw new IdpCryptoException("Error while querying file system", e);
    }
  }

  @Target(ElementType.PARAMETER)
  @Retention(RetentionPolicy.RUNTIME)
  @Documented
  public @interface Filename {

    String value();
  }
}
