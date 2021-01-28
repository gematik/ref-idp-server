package de.gematik.idp.server.services;

import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.pairing.PairingData;
import de.gematik.idp.server.pairing.PairingRepository;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PairingService {

    private final PairingRepository pairingRepository;
    private final ModelMapper modelMapper;

    public List<PairingDto> getPairingList(final String kvnr) {
        final List<PairingData> pairingDataList = pairingRepository.findByKvnr(kvnr);
        return pairingDataList.stream()
            .map(this::convertToDto)
            .collect(Collectors.toList());
    }

    public void deleteSelectedPairing(final String kvnr, final String id) {
        pairingRepository.deleteByKvnrAndId(kvnr, Long.valueOf(id));
    }

    public void deleteAllPairings(final String kvnr) {
        pairingRepository.deleteByKvnr(kvnr);
    }

    public Long insertPairing(final PairingDto data) {
        data.setId(null);
        return pairingRepository.save(convertToEntity(data)).getId();
    }

    public Optional<PairingDto> getPairingDtoForKvnrAndDevice(final String kvnr, final String deviceManufacturer) {
        return pairingRepository
            .findByKvnrAndDeviceManufacturer(kvnr, deviceManufacturer)
            .map(this::convertToDto);
    }

    private PairingDto convertToDto(final PairingData pairingData) {
        return modelMapper.map(pairingData, PairingDto.class);
    }

    private PairingData convertToEntity(final PairingDto pairingDto) {
        return modelMapper.map(pairingDto, PairingData.class);
    }
}

