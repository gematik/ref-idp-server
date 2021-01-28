package de.gematik.idp.server.services;

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.idp.server.data.PairingDto;
import java.time.ZonedDateTime;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Transactional
@TestPropertySource(properties = {
    "spring.jpa.hibernate.ddl-auto=validate"
})
public class PairingServiceTest {

    private static final String test_kvnr = "123";

    @Autowired
    private PairingService pairingService;

    @Test
    public void insertPairing_ValidateEntry() {
        createPairingDataEntry();
        assertThat(pairingService.getPairingList(test_kvnr)).isNotEmpty();
    }

    @Test
    public void searchPairing_ValidateEntry() {
        createPairingDataEntry();
        final PairingDto pairingData = searchPairingData(test_kvnr);
        assertThat(pairingData).isNotNull();
        //FIXME: Wegen unterschiedlichen Timestamps beim Write/Read wird vorerst kein Equals gebaut,
        //      was aber nach Bugfix nachgebaut wird.
    }

    private PairingDto searchPairingData(final String kvnr) {
        return pairingService.getPairingList(kvnr).stream().findAny().orElseThrow();
    }

    private void createPairingDataEntry() {
        final PairingDto pairingDto = PairingDto.builder()
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
        pairingService.insertPairing(pairingDto);
    }


}
