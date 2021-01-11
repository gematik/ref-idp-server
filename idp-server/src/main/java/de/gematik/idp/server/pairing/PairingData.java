package de.gematik.idp.server.pairing;

import java.time.ZonedDateTime;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "pairing", schema = "IDP")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PairingData {

    @Id
    @Column(name = "id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "kvnr")
    private String kvnr;
    @Column(name = "serial")
    private String serial;
    @Column(name = "device_manufacturer")
    private String deviceManufacturer;
    @Column(name = "device_model")
    private String deviceModel;
    @Column(name = "device_os")
    private String deviceOS;
    @Column(name = "device_version")
    private String deviceVersion;
    @Column(name = "device_name")
    private String deviceName;
    @Column(name = "device_biometry")
    private String deviceBiometry;
    @Column(name = "puk_se_sig")
    private String pukSeB64;
    @Column(name = "timestamp_pairing")
    private ZonedDateTime timestampPairing;
    @Column(name = "timestamp_smartcard_auth")
    private ZonedDateTime timestampSmartcardAuth;

}
