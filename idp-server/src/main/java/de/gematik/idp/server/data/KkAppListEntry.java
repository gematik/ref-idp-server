package de.gematik.idp.server.data;

import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Builder
@RequiredArgsConstructor
@Getter
public class KkAppListEntry {

    private final String kkAppName;
    private final String kkAppUri;
    private final String kkAppId;
}
