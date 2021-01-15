package de.gematik.idp.test.ide;

import cucumber.api.CucumberOptions;
import de.gematik.idp.test.steps.helpers.TestEnvironmentConfigurator;
import java.io.IOException;
import net.serenitybdd.cucumber.CucumberWithSerenity;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;

@RunWith(CucumberWithSerenity.class)
@CucumberOptions(
    strict = true,
    features = {"src/test/resources/features"},
    monochrome = false,
    glue = {"de.gematik.idp.test.steps"})
public class JUnitHookForIde {

    @BeforeClass
    public static void setupClass() throws IOException {
        TestEnvironmentConfigurator.initializeTestEnvironment();
    }
}