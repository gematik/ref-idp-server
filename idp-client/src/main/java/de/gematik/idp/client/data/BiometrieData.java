package de.gematik.idp.client.data;

import java.time.ZonedDateTime;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

@ToString
@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class BiometrieData {

    @Builder.Default
    private String id = "";
    @Builder.Default
    private String kvnr = "anyKvnr";
    @Builder.Default
    private String serial = "anySerial";
    @Builder.Default
    private String deviceManufacturer = "anyManufacture";
    @Builder.Default
    private String deviceModel = "anyModel";
    @Builder.Default
    private String deviceOS = "anyOS";
    @Builder.Default
    private String deviceVersion = "anyVersion";
    @Builder.Default
    private String deviceName = "anyName";
    @Builder.Default
    private String deviceBiometry = "anyDevice";
    @Builder.Default
    private String pukSeB64 = "anyPukSe";
    @Builder.Default
    private String timestampPairing = "";
    @Builder.Default
    private String timestampSmartcardAuth = "";

}
