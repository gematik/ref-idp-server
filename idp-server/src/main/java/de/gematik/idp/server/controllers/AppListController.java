package de.gematik.idp.server.controllers;

import static de.gematik.idp.IdpConstants.APPLIST_ENDPOINT;
import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.server.data.KkAppList;
import java.util.Map;
import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AppListController {

    private final IdpKey discSig;
    private IdpJwtProcessor jwtProcessor;
    private final KkAppList kkAppList;

    @PostConstruct
    public void setUp() {
        jwtProcessor = new IdpJwtProcessor(discSig.getIdentity());
    }

    @GetMapping(value = APPLIST_ENDPOINT, produces = "application/jwt;charset=UTF-8")
    public String getAppList(final HttpServletRequest request) {
        return signAppList(kkAppList.getListAsJson().toString());
    }


    private String signAppList(final String list) {

        return jwtProcessor
            .buildJws(
                list, Map.ofEntries(Map.entry("typ", "JWT")), true)
            .getRawString();

    }

}
