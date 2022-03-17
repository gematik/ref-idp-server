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

package de.gematik.idp.fachdienst.services;


import static de.gematik.idp.IdpConstants.FED_SIGNED_JWKS_ENDPOINT;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.fachdienst.EntityStatement;
import de.gematik.idp.data.fachdienst.FederationEntity;
import de.gematik.idp.data.fachdienst.Metadata;
import de.gematik.idp.data.fachdienst.OpenidRelyingParty;
import java.time.ZonedDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;

@RequiredArgsConstructor
public class EntityStatementBuilder {

    @Autowired
    FederationPrivKey entityStatementSigKey;
    private static final int ENTITY_STATEMENT_TTL_DAYS = 1;

    public EntityStatement buildEntityStatement(final String serverUrl) {
        final ZonedDateTime currentTime = ZonedDateTime.now();
        return EntityStatement.builder()
            .exp(currentTime.plusDays(ENTITY_STATEMENT_TTL_DAYS).toEpochSecond())
            .iat(currentTime.toEpochSecond())
            .iss(serverUrl)
            .sub(serverUrl)
            .jwks(JwtHelper.getJwks(entityStatementSigKey))
            .authorityHints(new String[]{"todo Bezeichnung des Federation Master"})
            .metadata(getMetadata(serverUrl))
            .build();
    }

    private Metadata getMetadata(final String serverUrl) {
        final OpenidRelyingParty openidRelyingParty = OpenidRelyingParty.builder()
            .signedJwksUri(serverUrl + FED_SIGNED_JWKS_ENDPOINT)
            .organizationName("Fachdienst007 des FedIdp POCs")
            .clientName("Fachdienst007")
            .logoUri(serverUrl + "/noLogoYet")
            .redirectUris(new String[]{"https://Fachdienst007.de/client"})
            .responseTypes(new String[]{"code"})
            .clientRegistrationTypes(new String[]{"automatic"})
            .grantTypes(new String[]{"authorization_code"})
            .requirePushedAuthorizationRequests(true)
            .tokenEndpointAuthMethod("private_key_jwt")
            .tokenEndpointAuthSigningAlg("ES256")
            .idTokenSignedResponseAlg("ES256")
            .idTokenEncryptedResponseAlg("ECDH-ES")
            .idTokenEncryptedResponseEnc("A256GCM")
            .build();
        final FederationEntity federationEntity = FederationEntity.builder()
            .name("Fachdienst007")
            .contacts("Support@Fachdienst007.de")
            .homepageUri("https://Fachdienst007.de")
            .build();
        return Metadata.builder()
            .openidRelyingParty(openidRelyingParty)
            .federationEntity(federationEntity)
            .build();
    }

}
