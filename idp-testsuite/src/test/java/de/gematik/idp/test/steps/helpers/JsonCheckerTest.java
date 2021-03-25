package de.gematik.idp.test.steps.helpers;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.Test;

public class JsonCheckerTest {

    final JsonChecker check = new JsonChecker();

    @Test
    public void testOptionalJSONAttirbuteFlatOKMissing() {
        check.assertJsonShouldMatchInAnyOrder(
            "{ attr1: 'val1' }",
            "{ attr1: 'val1', ____attr2: 'val2' }");
    }

    @Test
    public void testOptionalJSONAttributeFlatOKEquals() {
        check.assertJsonShouldMatchInAnyOrder(
            "{ attr1:'val1', attr2:'val2' }",
            "{ attr1: 'val1', ____attr2: 'val2' }");
    }

    @Test
    public void testOptionalJSONAttirbuteFlatOKMatches() {
        check.assertJsonShouldMatchInAnyOrder(
            "{ attr1:'val1', attr2:'val2' }",
            "{ attr1: 'val1', ____attr2: 'v.*' }");
    }

    @Test
    public void testOptionalJSONAttirbuteFlatNOKNotEquals() {
        assertThatThrownBy(() -> check.assertJsonShouldMatchInAnyOrder(
            "{ attr1:'val1', attr2:'val2' }",
            "{ attr1: 'val1', ____attr2: 'valXXX' }"))
            .isInstanceOf(AssertionError.class);
    }

    @Test
    public void testOptionalJSONAttirbuteFlatNOKMismatch() {
        assertThatThrownBy(() -> check.assertJsonShouldMatchInAnyOrder(
            "{ attr1:'val1', attr2:'val2' }",
            "{ attr1: 'val1', ____attr2: 'v?\\\\d' }"))
            .isInstanceOf(AssertionError.class);
    }

}
