package de.gematik.idp.server.services;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.when;

import de.gematik.idp.server.configuration.IdpConfiguration;
import de.gematik.idp.server.data.IdpClientConfiguration;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ClientRegistrationServiceTest {

    private IdpClientConfiguration clientConfiguration = IdpClientConfiguration.builder().redirectUri("eRezeptUrl").returnSsoToken(true).build();

    @Mock
    private Map<String, IdpClientConfiguration> registeredClient;
    @Mock
    private IdpConfiguration configuration;
    @InjectMocks
    private ClientRegistrationService clientRegistrationService ;

    @BeforeEach
    public void init() {
        when(configuration.getRegisteredClient()).thenReturn(registeredClient);
    }

    @Test
    public void validateClientIdWithNullValue_ExpectCorrectError() {
        when(registeredClient.get(null)).thenReturn(null);
        assertThat(clientRegistrationService.getClientConfiguration(null))
            .isEmpty();
    }

    @Test
    public void validateClientIdWithInvalidValue_ExpectCorrectError() {
        when(registeredClient.get("eRezeptApp")).thenReturn(clientConfiguration);
        assertThat(clientRegistrationService.getClientConfiguration("eRezeptApp"))
            .hasValue(clientConfiguration);
    }
}