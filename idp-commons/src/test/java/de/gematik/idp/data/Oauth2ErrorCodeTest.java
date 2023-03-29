package de.gematik.idp.data;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import de.gematik.idp.data.fedidp.Oauth2ErrorCode;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

class Oauth2ErrorCodeTest {

  @SneakyThrows
  @Test
  void constructInvalidGrantFromStringValid() {
    final Oauth2ErrorCode oauth2ErrorCode =
        new ObjectMapper().readValue("\"invalid_grant\"", Oauth2ErrorCode.class);
    assertThat(oauth2ErrorCode).isNotNull();
  }

  @SneakyThrows
  @Test
  void constructInvalidScopeFromStringValid() {
    final Oauth2ErrorCode oauth2ErrorCode =
        new ObjectMapper().readValue("\"invalid_scope\"", Oauth2ErrorCode.class);
    assertThat(oauth2ErrorCode).isNotNull();
  }

  @SneakyThrows
  @Test
  void constructFromStringInvalid() {
    assertThatThrownBy(
            () -> new ObjectMapper().readValue("\"Invalid_grant\"", Oauth2ErrorCode.class))
        .isInstanceOf(InvalidFormatException.class);
  }
}
