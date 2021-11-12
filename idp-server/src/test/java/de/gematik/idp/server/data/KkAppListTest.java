package de.gematik.idp.server.data;

import static org.assertj.core.api.Assertions.assertThat;
import kong.unirest.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class KkAppListTest {

    @Test
    void getListAsJsonStringCheckMapToJson() {
        final KkAppList kkAppList = new KkAppList();

        kkAppList.add(KkAppListEntry.builder()
            .kkAppId("id1")
            .kkAppName("Gematik KK")
            .kkAppUri("www.tk42.de")
            .build());

        kkAppList.add(KkAppListEntry.builder()
            .kkAppId("id2")
            .kkAppName("meine krankenkasse")
            .kkAppUri("www.myKK.de")
            .build());

        System.out.println(kkAppList.getListAsJson());
        final JSONObject json = kkAppList.getListAsJson();
        assertThat(json.getJSONArray("kk_app_list").length()).isEqualTo(2);
    }

}
