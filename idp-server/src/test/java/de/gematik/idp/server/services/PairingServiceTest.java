package de.gematik.idp.server.services;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.pairing.PairingData;
import de.gematik.idp.server.pairing.PairingRepository;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {
    "spring.jpa.hibernate.ddl-auto=validate"
})
public class PairingServiceTest {

    private static final String test_kvnr = "123";

    @Autowired
    private PairingService pairingService;
    @Autowired
    private PairingRepository pairingRepository;

    @Test
    public void insertPairing_ValidateEntry() {
        pairingService.insertPairing(createPairingData());
        assertThat(pairingService.getPairingList(test_kvnr)).isNotEmpty();
    }

    private PairingDto createPairingData() {
        return PairingDto.builder()
            .kvnr(test_kvnr)
            .deviceBiometry("TouchID")
            .deviceManufacturer("samsung")
            .deviceModel("s8")
            .deviceOS("android")
            .deviceName("Peters Fon")
            .deviceVersion("10")
            .pukSeB64("132164g6d4gfd35g15311")
            .serial("123456789")
            .timestampPairing(ZonedDateTime.now().minusDays(1))
            .timestampSmartcardAuth(ZonedDateTime.now())
            .build();
    }

    @Test
    public void searchPairing_ValidateEntry() {
        PairingDto pairingDto = createPairingData();
        pairingService.insertPairing(pairingDto);
        PairingDto pairingData = searchPairingData(test_kvnr);
        assertThat(pairingData).isNotNull();
        //FIXME: Wegen unterschiedlichen Timestamps beim Write/Read wird vorerst kein Equals gebaut,
        //      was aber nach Bugfix nachgebaut wird.
    }

    private PairingDto searchPairingData( String kvnr) {
        return pairingService.getPairingList(kvnr).stream().findAny().orElseThrow();
    }
}
