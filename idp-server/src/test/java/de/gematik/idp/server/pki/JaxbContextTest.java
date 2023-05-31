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

package de.gematik.idp.server.pki;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

import de.gematik.pki.gemlibpki.tsl.TslConverter;
import eu.europa.esig.trustedlist.jaxb.tsl.TrustStatusListType;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import org.junit.jupiter.api.Test;

/** Creation of TucPki018Verifier needs a JAXBContext. */
class JaxbContextTest {
  private static final String TSL_FILEPATH = "TSL_default.xml";

  @Test
  void convertTsl() throws IOException, URISyntaxException {
    final byte[] tslBytes = getTslFromResources();
    final TrustStatusListType tsl = TslConverter.bytesToTsl(tslBytes);
    assertThat(tsl.getId()).isNotEmpty();
  }

  private byte[] getTslFromResources() throws IOException, URISyntaxException {
    return Files.readAllBytes(
        Path.of(
            Objects.requireNonNull(
                    getClass().getClassLoader().getResource(TSL_FILEPATH),
                    "Read TSL from resources failed.")
                .toURI()));
  }
}
