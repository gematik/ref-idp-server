package de.gematik.idp.test.steps;

import de.gematik.idp.test.steps.helpers.CucumberValuesConverter;
import de.gematik.idp.test.steps.model.Context;
import de.gematik.idp.test.steps.model.ContextKey;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.And;
import io.cucumber.java.en.When;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Steps;

@Slf4j
public class BiometricsGlue {

    @Steps
    IdpBiometricsSteps biosteps;

    @Steps
    CucumberValuesConverter cucumberValuesConverter;


    @When("I create a device information token with")
    public void iCreateADeviceInformationTokenWith(final DataTable data) {
        final Map<String, String> map = cucumberValuesConverter.getMapFromDatatable(data);
        Context.getThreadContext().put(ContextKey.DEVICE_INFO, map);
    }

    @And("I create pairing data with")
    public void iCreatePairingDataWith(final DataTable data) {
        Context.getThreadContext().put(ContextKey.PAIRING_DATA, cucumberValuesConverter.getMapFromDatatable(data));
    }

    @And("I create authentication data with")
    public void iCreateAuthenticationDataWith(final DataTable data) {
        biosteps.createAuthenticationData(cucumberValuesConverter.getMapFromDatatable(data));
    }

    @And("I sign pairing data with {string}")
    public void iSignPairingDataWithCert(final String certFile) {
        biosteps.signPairingData(certFile);
    }

    @And("I sign authentication data with {string}")
    public void iSignAuthenticationDataWithKey(final String keyFile) {
        biosteps.signAuthenticationData(keyFile, "1.0");
    }

    @And("I sign authentication data with {string} and version {string}")
    public void iSignAuthenticationDataWithKeyAndVersion(final String keyFile, final String version) {
        biosteps.signAuthenticationData(keyFile, version);
    }

    @When("I register the device with {string}")
    public void iRegisterTheDeviceWithCert(final String certFile) {
        biosteps.registerDeviceWithCert(certFile, "1.0");
    }

    @When("I register the device with {string} and version {string}")
    public void iRegisterTheDeviceWithAndVersion(final String keyVerifier, final String versionReg) {
        biosteps.registerDeviceWithCert(keyVerifier, versionReg);
    }

    @When("I deregister the device with {string}")
    public void iDeregisterTheDeviceWith(final String keyVerifier) {
        biosteps.deregisterDeviceWithKey(keyVerifier);
    }

    @And("I request all pairings")
    public void iRequestAllPairings() {
        biosteps.requestAllPairings();
    }
}
