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

package de.gematik.idp.server;

import de.gematik.idp.authentication.AuthenticationChallengeBuilder;
import de.gematik.idp.authentication.AuthenticationChallengeVerifier;
import de.gematik.idp.authentication.AuthenticationTokenBuilder;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.controllers.IdpKey;
import de.gematik.idp.server.exceptions.IdpServerStartupException;
import de.gematik.idp.server.services.DiscoveryDocumentBuilder;
import de.gematik.idp.token.AccessTokenBuilder;
import de.gematik.idp.token.IdTokenBuilder;
import de.gematik.idp.token.SsoTokenBuilder;
import de.gematik.pki.certificate.CertificateProfile;
import de.gematik.pki.certificate.TucPki018Verifier;
import de.gematik.pki.tsl.TslInformationProvider;
import de.gematik.pki.tsl.TslReader;
import de.gematik.pki.tsl.TspService;
import java.security.Key;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.modelmapper.ModelMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class FlowBeanCreation {

    private final IdpJwtProcessor idpSigProcessor;
    private final IdpKey idpEnc;
    private final IdpKey idpSig;
    private final Key symmetricEncryptionKey;
    private final ServerUrlService serverUrlService;
    private final IdpConfiguration idpConfiguration;

    @Bean
    public AuthenticationTokenBuilder authenticationTokenBuilder() {
        return new AuthenticationTokenBuilder(idpSigProcessor, symmetricEncryptionKey,
            authenticationChallengeVerifier());
    }

    @Bean
    public AccessTokenBuilder accessTokenBuilder() {
        return new AccessTokenBuilder(idpSigProcessor, serverUrlService.determineServerUrl(), getSubjectSaltValue());
    }

    @Bean
    public IdTokenBuilder idTokenBuilder() {
        return new IdTokenBuilder(idpSigProcessor, serverUrlService.determineServerUrl(), getSubjectSaltValue());
    }

    @Bean
    public SsoTokenBuilder ssoTokenBuilder() {
        return new SsoTokenBuilder(idpSigProcessor, serverUrlService.getIssuerUrl(),
            symmetricEncryptionKey);
    }

    @Bean
    public DiscoveryDocumentBuilder discoveryDocumentBuilder() {
        return new DiscoveryDocumentBuilder();
    }

    @Bean
    public AuthenticationChallengeBuilder authenticationChallengeBuilder() {
        return AuthenticationChallengeBuilder.builder()
            .serverSigner(idpSigProcessor)
            .uriIdpServer(serverUrlService.determineServerUrl())
            .userConsentConfiguration(idpConfiguration.getUserConsent())
            .build();
    }

    @Bean
    public AuthenticationChallengeVerifier authenticationChallengeVerifier() {
        return AuthenticationChallengeVerifier.builder()
            .serverIdentity(idpSig.getIdentity())
            .build();
    }

    @Bean
    public ModelMapper modelMapper() {
        return new ModelMapper();
    }

    @Bean
    public TucPki018Verifier certificateVerifier() {
        final List<TspService> tspServiceTypeList = new TslInformationProvider(
            new TslReader().getTrustServiceStatusList("TSL_default.xml")
                .orElseThrow(() -> new IdpServerStartupException("Error while reading TSL")))
            .getTspServices();

        return TucPki018Verifier.builder()
            .productType(idpConfiguration.getProductTypeDisplayString())
            .tspServiceList(tspServiceTypeList)
            .certificateProfiles(List.of(CertificateProfile.C_CH_AUT_RSA, CertificateProfile.C_CH_AUT_ECC,
                CertificateProfile.C_HCI_AUT_RSA, CertificateProfile.C_HCI_AUT_ECC,
                CertificateProfile.C_HP_AUT_RSA, CertificateProfile.C_HP_AUT_ECC))
            .build();
    }

    private String getSubjectSaltValue() {
        return Optional.ofNullable(idpConfiguration.getSubjectSaltValue())
            .filter(StringUtils::isNotEmpty)
            .orElseThrow(() -> new IdpServerStartupException("Missing configuration value: idp.subjectSaltValue"));
    }
}
