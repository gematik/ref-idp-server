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

package de.gematik.idp.fedmaster;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.FederationPubKey;
import de.gematik.idp.fedmaster.configuration.FedMasterConfiguration;
import de.gematik.idp.fedmaster.configuration.FederationKeyConfig;
import de.gematik.idp.fedmaster.exceptions.FedmasterException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.StreamUtils;

@Configuration
@RequiredArgsConstructor
public class KeyConfiguration {

    private final ResourceLoader resourceLoader;
    private final FedMasterConfiguration fedMasterConfiguration;


    @Bean
    public FederationPrivKey sigKey() {
        return getFederationPrivKey(fedMasterConfiguration.getSigKeyConfig());
    }

    // TODO: change config arg
    @Bean
    public FederationPubKey fachdienstSigKey() {
        return getFederationPubKey(fedMasterConfiguration.getFachdienstSigKeyConfig());
    }

    // TODO: change config arg
    @Bean
    public FederationPubKey idpSigKey() {
        return getFederationPubKey(fedMasterConfiguration.getIdpSigKeyConfig());
    }

    @Bean
    public IdpJwtProcessor jwtProcessor() {
        return new IdpJwtProcessor(sigKey().getIdentity());
    }

    private FederationPrivKey getFederationPrivKey(final FederationKeyConfig keyConfiguration) {
        final Resource resource = resourceLoader.getResource(keyConfiguration.getFileName());
        try (final InputStream inputStream = resource.getInputStream()) {
            final PkiIdentity pkiIdentity = CryptoLoader.getIdentityFromP12(
                StreamUtils.copyToByteArray(inputStream), "00");

            pkiIdentity.setKeyId(Optional.ofNullable(keyConfiguration.getKeyId()));
            pkiIdentity.setUse(Optional.ofNullable(keyConfiguration.getUse()));
            return new FederationPrivKey(pkiIdentity);
        } catch (final IOException e) {
            throw new FedmasterException(
                "Error while loading Key from resource '" + keyConfiguration.getFileName() + "'", e);
        }
    }

    // TODO: pub (no p12)
    private FederationPubKey getFederationPubKey(final FederationKeyConfig keyConfiguration) {
        final Resource resource = resourceLoader.getResource(keyConfiguration.getFileName());
        try (final InputStream inputStream = resource.getInputStream()) {
            final PkiIdentity pkiIdentity = CryptoLoader.getIdentityFromP12(
                StreamUtils.copyToByteArray(inputStream), "00");

            pkiIdentity.setKeyId(Optional.ofNullable(keyConfiguration.getKeyId()));
            pkiIdentity.setUse(Optional.ofNullable(keyConfiguration.getUse()));
            return new FederationPubKey(pkiIdentity, keyConfiguration.getIssuer(), keyConfiguration.getType(),
                keyConfiguration.getUrl());
        } catch (final IOException e) {
            throw new FedmasterException(
                "Error while loading Key from resource '" + keyConfiguration.getFileName() + "'", e);
        }
    }


}
