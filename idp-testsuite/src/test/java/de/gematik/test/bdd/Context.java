package de.gematik.test.bdd;

import static org.assertj.core.api.Assertions.assertThat;
import de.gematik.idp.test.steps.model.DiscoveryDocument;
import io.restassured.response.Response;
import org.json.JSONObject;

public class Context extends ThreadedContextProvider {

    private static final Context SINGLETON = new Context();

    public static Context get() {
        return SINGLETON;
    }
    
    public static Response getCurrentResponse() {
        assertThat(get().get(ContextKey.RESPONSE)).withFailMessage("No Response in context!")
            .isNotNull();
        return (Response) get().get(ContextKey.RESPONSE);
    }

    public static JSONObject getCurrentClaims() {
        assertThat(get().get(ContextKey.CLAIMS)).withFailMessage("No Claims in context!")
            .isNotNull();
        return (JSONObject) get().get(ContextKey.CLAIMS);
    }

    public static DiscoveryDocument getDiscoveryDocument() {
        assertThat(get().get(ContextKey.DISC_DOC))
            .withFailMessage("No Discovery Document in context!")
            .isNotNull();
        return (DiscoveryDocument) (get().get(ContextKey.DISC_DOC));
    }

}
