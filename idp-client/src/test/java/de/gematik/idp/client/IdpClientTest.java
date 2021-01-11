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

package de.gematik.idp.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import de.gematik.idp.client.data.DiscoveryDocumentResponse;
import de.gematik.idp.crypto.model.PkiIdentity;
import de.gematik.idp.tests.PkiKeyResolver;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(PkiKeyResolver.class)
public class IdpClientTest {

    private IdpClient idpClient;
    private AuthenticatorClient authenticatorClient;

    @BeforeEach
    public void init(final PkiIdentity ecc) {
        authenticatorClient = mock(AuthenticatorClient.class);
        doReturn(DiscoveryDocumentResponse.builder()
            .keyId("foo")
            .verificationCertificate("bar")
            .authorizationEndpoint("fdsa")
            .serverTokenCertificate(ecc.getCertificate())
            .tokenEndpoint("fdsafds")
            .build())
            .when(authenticatorClient)
            .retrieveDiscoveryDocument(anyString());

        doAnswer(call -> ((Function) call.getArguments()[1]).apply(null))
            .when(authenticatorClient)
            .doAuthorizationRequest(any(), any(), any());

        idpClient = IdpClient.builder()
            .discoveryDocumentUrl("fjnkdslaö")
            .authenticatorClient(authenticatorClient)
            .build();

        idpClient.initialize();
    }

    @Test
    public void testBeforeCallback(final PkiIdentity ecc) {
        final AtomicInteger callCounter = new AtomicInteger(0);
        idpClient.setBeforeAuthorizationCallback(r -> callCounter.incrementAndGet());

        try {
            idpClient.login(ecc);
        } catch (final RuntimeException e) {
            //swallow
        }

        assertThat(callCounter.get())
            .isOne();
    }

    @Test
    public void testBeforeFunction(final PkiIdentity ecc) {
        final AtomicInteger callCounter = new AtomicInteger(0);
        idpClient.setBeforeAuthorizationMapper(r -> {
            callCounter.incrementAndGet();
            return r;
        });

        try {
            idpClient.login(ecc);
        } catch (final RuntimeException e) {
            //swallow
        }

        assertThat(callCounter.get())
            .isOne();
    }
}
