package de.gematik.idp.test.steps;

import de.gematik.idp.test.steps.model.Context;
import de.gematik.idp.test.steps.model.ContextKey;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.And;
import io.cucumber.java.en.When;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Steps;

@Slf4j
public class BiometricsGlue {

    @Steps
    IdpBiometricsSteps biosteps;


    @When("I create a device information token with")
    public void iCreateADeviceInformationTokenWith(final DataTable data) {
        Context.getThreadContext().put(ContextKey.DEVICE_INFO, biosteps.getMapFromDatatable(data));
    }

    @And("I create pairing data with")
    public void iCreatePairingDataWith(final DataTable data) {
        Context.getThreadContext().put(ContextKey.PAIRING_DATA, biosteps.getMapFromDatatable(data));
    }

    @And("I sign pairing data with {string}")
    public void iSignPairingDataWithCert(final String certFile) {
        biosteps.signPairingData(certFile);
    }

    @When("I register the device with {string}")
    public void iRegisterTheDeviceWithCert(final String certFile) {
        biosteps.registerDeviceWithCert(certFile);
    }
}
