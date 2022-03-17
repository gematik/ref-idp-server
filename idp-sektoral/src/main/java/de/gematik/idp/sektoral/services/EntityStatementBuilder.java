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

package de.gematik.idp.sektoral.services;

import static de.gematik.idp.IdpConstants.FEDIDP_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.FEDIDP_PAR_AUTH_ENDPOINT;
import static de.gematik.idp.IdpConstants.FEDIDP_TOKEN_ENDPOINT;
import static de.gematik.idp.IdpConstants.FED_SIGNED_JWKS_ENDPOINT;
import de.gematik.idp.data.FederationPrivKey;
import de.gematik.idp.data.JwtHelper;
import de.gematik.idp.data.fedidp.EntityStatement;
import de.gematik.idp.data.fedidp.FederationEntity;
import de.gematik.idp.data.fedidp.Metadata;
import de.gematik.idp.data.fedidp.OpenidProvider;
import java.time.ZonedDateTime;
import kong.unirest.json.JSONObject;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;

@RequiredArgsConstructor
public class EntityStatementBuilder {

    @Autowired
    FederationPrivKey entityStatementSigKey;
    private static final int ENTITY_STATEMENT_TTL_DAYS = 7;

    public EntityStatement buildEntityStatement(final String serverUrl) {
        final ZonedDateTime currentTime = ZonedDateTime.now();
        return EntityStatement.builder()
            .exp(currentTime.plusDays(ENTITY_STATEMENT_TTL_DAYS).toEpochSecond())
            .iat(currentTime.toEpochSecond())
            .iss(serverUrl)
            .sub("https://idp4711.de")
            .jwks(JwtHelper.getJwks(entityStatementSigKey))
            .authorityHints(new String[]{"todo Bezeichnung des Federation Master"})
            .metadata(getMetadata(serverUrl))
            .build();
    }

    private Metadata getMetadata(final String serverUrl) {
        final OpenidProvider openidProvider = OpenidProvider.builder()
            .issuer(serverUrl)
            // TODO: wir müssen den Endpunkt bereitstellen
            .signedJwksUri(serverUrl + FED_SIGNED_JWKS_ENDPOINT)
            .organizationName("Föderierter IDP des POC")
            .logoUri(serverUrl + "/noLogoYet")
            .authorizationEndpoint(serverUrl + FEDIDP_AUTH_ENDPOINT)
            .tokenEndpoint(serverUrl + FEDIDP_TOKEN_ENDPOINT)
            .pushedAuthorizationRequestEndpoint(serverUrl + FEDIDP_PAR_AUTH_ENDPOINT)
            .clientRegistrationTypesSupported(new String[]{"automatic"})
            .subjectTypesSupported(new String[]{"public"})
            .responseTypesSupported(new String[]{"code"})
            .scopesSupported(new String[]{"openid"})
            .responseModesSupported(new String[]{"query"})
            .grantTypesSupported(new String[]{"authorization_code"})
            .requirePushedAuthorizationRequests(true)
            .tokenEndpointAuthMethodsSupported(new String[]{"private_key_jwt"})
            .tokenEndpointAuthSigningAlgValuesSupported(new String[]{"ES256"})
            .requestAuthenticationMethodsSupported(
                new JSONObject()
                    .put("ar", new String[]{"none"})
                    .put("par", new String[]{"private_key_jwt"})
                    .toString())
            .idTokenSigningAlgValuesSupported(new String[]{"ES256"})
            .idTokenEncryptionAlgValuesSupported(new String[]{"ECDH-ES"})
            .idTokenEncryptionEncValuesSupported(new String[]{"A256GCM"})
            .claimsSupported(new String[]{"TODO"})
            .claimsParameterSupported(new String[]{"TODO"})
            .userTypeSupported("IP")
            .build();
        final FederationEntity federationEntity = FederationEntity.builder()
            .name("idp4711")
            .contacts("support@idp4711.de")
            .homepageUri("https://idp4711.de")
            .build();
        return Metadata.builder()
            .openidProvider(openidProvider)
            .federationEntity(federationEntity)
            .build();
    }

}
