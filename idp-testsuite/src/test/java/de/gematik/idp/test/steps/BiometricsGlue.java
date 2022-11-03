/*
 * Copyright (c) 2022 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps;

import de.gematik.idp.test.steps.helpers.CucumberValuesConverter;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import io.cucumber.datatable.DataTable;
import io.cucumber.java.en.And;
import io.cucumber.java.en.When;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import net.thucydides.core.annotations.Steps;

@Slf4j
public class BiometricsGlue {

  @Steps IdpBiometricsSteps biosteps;

  @Steps CucumberValuesConverter cucumberValuesConverter;

  @When("IDP I create a device information token with")
  public void iCreateADeviceInformationTokenWith(final DataTable data) {
    final Map<String, String> map = cucumberValuesConverter.getMapFromDatatable(data);
    Context.get().put(ContextKey.DEVICE_INFO, map);
  }

  @And("IDP I create pairing data with")
  public void iCreatePairingDataWith(final DataTable data) {
    Context.get().put(ContextKey.PAIRING_DATA, cucumberValuesConverter.getMapFromDatatable(data));
  }

  @And("IDP I create authentication data with")
  public void iCreateAuthenticationDataWith(final DataTable data) {
    biosteps.createAuthenticationData(cucumberValuesConverter.getMapFromDatatable(data));
  }

  @And("IDP I sign pairing data with {string}")
  public void iSignPairingDataWithCert(final String certFile) {
    biosteps.signPairingData(certFile);
  }

  @And("IDP I sign authentication data with {string}")
  public void iSignAuthenticationDataWithKey(final String keyFile) {
    biosteps.signAuthenticationData(keyFile, "1.0");
  }

  @And("IDP I sign authentication data with {string} and version {string}")
  public void iSignAuthenticationDataWithKeyAndVersion(final String keyFile, final String version) {
    biosteps.signAuthenticationData(keyFile, version);
  }

  @When("IDP I register the device with {string}")
  public void iRegisterTheDeviceWithCert(final String certFile) {
    biosteps.registerDeviceWithCert(certFile, "1.0");
  }

  @When("IDP I register the device with {string} and version {string}")
  public void iRegisterTheDeviceWithAndVersion(final String keyVerifier, final String versionReg) {
    biosteps.registerDeviceWithCert(keyVerifier, versionReg);
  }

  @When("IDP I deregister the device with {string}")
  public void iDeregisterTheDeviceWith(final String keyVerifier) {
    biosteps.deregisterDeviceWithKey(keyVerifier);
  }

  @And("IDP I request all pairings")
  public void iRequestAllPairings() {
    biosteps.requestAllPairings();
  }
}
