package de.gematik.idp.test.ide;

import de.gematik.idp.test.steps.helpers.TestEnvironmentConfigurator;
import io.cucumber.junit.CucumberOptions;
import java.io.IOException;
import net.serenitybdd.cucumber.CucumberWithSerenity;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;

@RunWith(CucumberWithSerenity.class)
@CucumberOptions(
    strict = true,
    features = {"src/test/resources/features"},
    glue = {"de.gematik.idp.test.steps"})
public class JUnitHookForIde {

    @BeforeClass
    public static void setupClass() throws IOException {
        TestEnvironmentConfigurator.initializeTestEnvironment();
    }
}