package de.gematik.idp.server.data;

import java.time.ZonedDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PairingDto {

    private Long id;
    private String kvnr;
    private String serial;
    private String deviceManufacturer;
    private String deviceModel;
    private String deviceOS;
    private String deviceVersion;
    private String deviceName;
    private String deviceBiometry;
    private String pukSeB64;
    private ZonedDateTime timestampPairing;
    private ZonedDateTime timestampSmartcardAuth;

}