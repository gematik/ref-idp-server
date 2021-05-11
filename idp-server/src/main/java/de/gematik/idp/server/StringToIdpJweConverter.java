package de.gematik.idp.server;

import de.gematik.idp.token.IdpJwe;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class StringToIdpJweConverter implements Converter<String, IdpJwe> {

    @Override
    public IdpJwe convert(final String content) {
        return new IdpJwe(content);
    }
}
