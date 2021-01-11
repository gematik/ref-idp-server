package de.gematik.idp.test.steps.helpers;

import lombok.SneakyThrows;
import org.json.JSONException;
import org.json.JSONObject;

public class SerenityJSONObject extends JSONObject {

    public SerenityJSONObject(final JSONObject json) throws JSONException {
        super(json.toString());
    }

    public SerenityJSONObject(final String jsonStr) throws JSONException {
        super(jsonStr);
    }

    @Override
    @SneakyThrows
    public String toString() {
        return "\n" + super.toString(2) + "\n";
    }
}
