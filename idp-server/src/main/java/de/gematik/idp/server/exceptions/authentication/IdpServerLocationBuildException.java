/*
 * Copyright (Date see Readme), gematik GmbH
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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.idp.server.exceptions.authentication;

import de.gematik.idp.error.IdpErrorType;
import de.gematik.idp.server.exceptions.IdpServerException;
import org.springframework.http.HttpStatus;

public class IdpServerLocationBuildException extends IdpServerException {

  private static final long serialVersionUID = -4036426792758314390L;
  private static final String URI_BUILDER_ERROR =
      "Error during authentication building the token-location URL";

  public IdpServerLocationBuildException(final Exception e) {
    super(URI_BUILDER_ERROR, e, IdpErrorType.INVALID_REQUEST, HttpStatus.BAD_REQUEST);
  }
}
