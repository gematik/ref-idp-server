package de.gematik.idp.server.pairing;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PairingRepository extends JpaRepository<PairingData, Long> {

    long deleteByKvnr(String kvnr);

    long deleteByKvnrAndId(String kvnr, long id);

    List<PairingData> findByKvnr(String kvnr);

    Optional<PairingData> findByKvnrAndDeviceManufacturer(String kvnr, String deviceManufacturer);
}