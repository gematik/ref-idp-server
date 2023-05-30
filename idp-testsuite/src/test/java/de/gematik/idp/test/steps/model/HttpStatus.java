/*
 *  Copyright 2023 gematik GmbH
 *  
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *  
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps.model;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;

@Getter
@Slf4j
public class HttpStatus {

  // IDP specific status

  public static final HttpStatus NOCHECK = new HttpStatus(-1);

  public static final HttpStatus SUCCESS = new HttpStatus(-2);

  public static final HttpStatus FAIL = new HttpStatus(-3);

  public static final String CUCUMBER_REGEX =
      "failed state|successfully|unsuccessfully|[1-5][0-9]{2}";

  private int value;

  public HttpStatus(final String statusStr) {
    try {
      value = Integer.parseInt(statusStr);
    } catch (final Exception e) {
      switch (statusStr) {
        case "successfully":
          value = -2;
          break;
        case "unsuccessfully":
        case "failed state":
          value = -3;
          break;
        default:
          Assertions.fail("Invalid http status code string '" + statusStr + "'");
      }
    }
  }

  public HttpStatus(final int statusInt) {
    if (statusInt > 99) {
      value = statusInt;
    } else {
      switch (statusInt) {
        case -1:
        case -2:
        case -3:
          value = statusInt;
          break;
        default:
          Assertions.fail("Invalid http status code int '" + statusInt + "'");
      }
    }
  }

  public boolean equals(final HttpStatus hs) {
    return hs.getValue() == value;
  }

  @Override
  public String toString() {
    switch (value) {
      case -1:
        return "HTTP STATUS NO CHECK";
      case -2:
        return "HTTP STATUS SUCCESS";
      case -3:
        return "HTTP STATUS FAIL";
      default:
        return "HTTP STATUS CODE " + value;
    }
  }

  @SuppressWarnings("unused")
  public boolean is1xxInformational() {
    return value / 100 == 1;
  }

  @SuppressWarnings("unused")
  public boolean is2xxSuccessful() {
    return value / 100 == 2;
  }

  public boolean is3xxRedirection() {
    return value / 100 == 3;
  }

  public boolean is4xxClientError() {
    return value / 100 == 4;
  }

  public boolean is5xxServerError() {
    return value / 100 == 5;
  }

  public boolean isError() {
    return (is4xxClientError() || is5xxServerError());
  }
}
