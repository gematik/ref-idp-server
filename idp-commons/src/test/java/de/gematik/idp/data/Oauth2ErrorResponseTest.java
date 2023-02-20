package de.gematik.idp.data;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.InvalidFormatException;
import com.fasterxml.jackson.databind.exc.PropertyBindingException;
import de.gematik.idp.data.fedidp.Oauth2ErrorResponse;
import java.util.HashMap;
import java.util.List;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;

class Oauth2ErrorResponseTest {
  static final String OAUTH_2_ERROR_CODE_AS_STRING_VALID =
      "{\"status\":\"400\",\"error\":\"invalid_grant\"}";
  static final String OAUTH_2_ERROR_CODE_AS_STRING_NOSTATUS_VALID =
      "{\"error\":\"unauthorized_client\"}";
  static final String OAUTH_2_ERROR_CODE_AS_STRING_WITH_OPTIONAL_1_VALID =
      "{\"status\":\"401\",\"error\":\"invalid_client\",\"error_description\":\"something strange"
          + " happened\"}";
  static final String OAUTH_2_ERROR_CODE_AS_STRING_WITH_OPTIONAL_2_VALID =
      "{\"status\":\"402\",\"error\":\"invalid_request\",\"error_uri\":\"foo://example.com:8042/over/there?name=ferret#nose\"}";

  static final String OAUTH_2_ERROR_CODE_AS_STRING_WITH_OPTIONAL_1and2_VALID =
      "{\"status\":\"403\",\"error\":\"invalid_grant\",\"error_description\":\"something strange"
          + " happened again\",\"error_uri\":\"telnet://192.0.2.16:80/\"}";

  static final String OAUTH_2_ERROR_CODE_AS_STRING_INVALID_LETTER = "{\"error\":\"invalid_Grant\"}";
  static final String OAUTH_2_ERROR_CODE_AS_STRING_INVALID_PARAM =
      "{\"timestamp\":\"2023-02-16T11:26:09.900+00:00\",\"status\":\"400\",\"error\":\"Bad"
          + " Request\",\"path\":\"/auth\"}";

  @SneakyThrows
  @Test
  void constructFromStringValid() {
    final List<String> validJson =
        List.of(
            OAUTH_2_ERROR_CODE_AS_STRING_VALID,
            OAUTH_2_ERROR_CODE_AS_STRING_NOSTATUS_VALID,
            OAUTH_2_ERROR_CODE_AS_STRING_WITH_OPTIONAL_1_VALID,
            OAUTH_2_ERROR_CODE_AS_STRING_WITH_OPTIONAL_2_VALID,
            OAUTH_2_ERROR_CODE_AS_STRING_WITH_OPTIONAL_1and2_VALID);
    for (final String json : validJson) {
      final Oauth2ErrorResponse oauth2ErrorResponse =
          new ObjectMapper().readValue(json, Oauth2ErrorResponse.class);
      assertThat(oauth2ErrorResponse).isNotNull();
    }
  }

  @SneakyThrows
  @Test
  void constructFromStringInvalid() {
    assertThatThrownBy(
            () ->
                new ObjectMapper()
                    .readValue(
                        OAUTH_2_ERROR_CODE_AS_STRING_INVALID_LETTER, Oauth2ErrorResponse.class))
        .isInstanceOf(InvalidFormatException.class);
    assertThatThrownBy(
            () ->
                new ObjectMapper()
                    .readValue(
                        OAUTH_2_ERROR_CODE_AS_STRING_INVALID_PARAM, Oauth2ErrorResponse.class))
        .isInstanceOf(PropertyBindingException.class);
  }

  @SuppressWarnings("unchecked")
  @SneakyThrows
  @Test
  void constructHashMap() {
    assertThat(
            new ObjectMapper()
                .readValue(OAUTH_2_ERROR_CODE_AS_STRING_WITH_OPTIONAL_1_VALID, HashMap.class))
        .hasSize(3);
  }
}
