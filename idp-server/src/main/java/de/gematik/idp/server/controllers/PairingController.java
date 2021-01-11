package de.gematik.idp.server.controllers;

import static de.gematik.idp.IdpConstants.PAIRING_ENDPOINT;

import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.data.PairingDto;
import de.gematik.idp.server.exceptions.IdpServerException;
import de.gematik.idp.server.services.PairingService;
import de.gematik.idp.server.validation.ValidateClientSystem;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import java.util.List;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@Transactional
@Validated
@Api(tags = {
    "Pairing-Dienst"}, description = "REST Endpunkte Abrufen, Einfügen und löschen von Pairing Daten")
public class PairingController {

    private final PairingService pairingService;

    @GetMapping(PAIRING_ENDPOINT + "/{kvnr}")
    @ApiOperation(httpMethod = "GET", value = "Endpunkt für Abrufen der Pairingdaten", notes = "Es werden zur übergebenen KVNR alle Pairingdaten abgerufen.", response = List.class)
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Pairingdaten erhalten"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public List<PairingDto> getAllPairingsForKvnr(
        @PathVariable("kvnr") @ApiParam(value = "Krankenversichertennummer") @Pattern(regexp = "\\d{10}", message = "Invalid KVNR!") final String kvnr) {
        return pairingService.getPairingList(kvnr);
    }

    @DeleteMapping(PAIRING_ENDPOINT + "/{kvnr}")
    @ApiOperation(httpMethod = "DELETE", value = "Endpunkt für das Löschen aller Pairingdaten zu einer KVNR", notes = "Es werden zur übergebenen KVNR alle gespeicherten Pairingdaten gelöscht. ")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Pairingdaten gelöscht"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public void deleteAllPairingsForKvnr(
        @PathVariable("kvnr") @ApiParam(value = "Krankenversichertennummer") @Pattern(regexp = "\\d{10}", message = "Invalid KVNR!") final String kvnr) {
        pairingService.deleteAllPairings(kvnr);
    }

    @DeleteMapping(PAIRING_ENDPOINT + "/{kvnr}/{id}")
    @ApiOperation(httpMethod = "DELETE", value = "Endpunkt für das Löschen eines spezifischen Pairingdatensatzes", notes = "Es wird zur übergebenen KVNR und ID der entsprechende Pairingdatensatz gelöscht. ")
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Pairingdaten gelöscht"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public void deleteSinglePairing(
        @PathVariable("kvnr") @ApiParam(value = "Krankenversichertennummer") @Pattern(regexp = "\\d{10}", message = "Invalid KVNR!") final String kvnr,
        @PathVariable(value = "id") @ApiParam(value = "PairingID") final String pairingID) {
        pairingService.deleteSelectedPairing(kvnr, pairingID);
    }

    @PutMapping(PAIRING_ENDPOINT + "/{kvnr}")
    @ApiOperation(httpMethod = "PUT", value = "Endpunkt zum Hinzufügen von Pairingdaten", notes = "Die hier engereichten Pairingdaten werden in der Pairing-DB hinterlegt. Ist dies erfolgreich, wird die ID für den DB-Eintrag zurückgegeben.", response = String.class)
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Erfolgreich Pairingdaten hinzugefügt"),
        @ApiResponse(responseCode = "400", description = "Ungültige Anfrage (Parameter fehlen/ungültig)"),
        @ApiResponse(responseCode = "403", description = "Nicht erlaubter Zugriff"),
        @ApiResponse(responseCode = "404", description = "Nicht gefunden - Methodenaufruf nicht korrekt")
    })
    @ValidateClientSystem
    public String insertPairing(
        @RequestBody @ApiParam(value = "Pairingdaten") @NotNull final PairingDto pairingData) {
        if (pairingData.getKvnr().isEmpty()) {
            throw new IdpServerException(IdpErrorType.MISSING_PARAMETERS, HttpStatus.BAD_REQUEST);
        }
        return String.valueOf(pairingService.insertPairing(pairingData));
    }

}
