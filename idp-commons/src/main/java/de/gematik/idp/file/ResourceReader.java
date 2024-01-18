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

package de.gematik.idp.file;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.Objects;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
public final class ResourceReader {

  public static File getFileFromResourceAsTmpFile(final String resourcePath) throws IOException {
    final InputStream resourceStream =
        Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
    Objects.requireNonNull(resourceStream);
    @SuppressWarnings("java:S5443")
    final File tempFile = File.createTempFile("temp", ".idp");
    tempFile.deleteOnExit();
    Files.copy(resourceStream, tempFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    return tempFile;
  }
}
