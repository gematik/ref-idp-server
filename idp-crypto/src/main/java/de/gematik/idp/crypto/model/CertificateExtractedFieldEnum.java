/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.crypto.model;

public enum CertificateExtractedFieldEnum {
    PROFESSION_OID("professionOID"),
    GIVEN_NAME("given_name"),
    FAMILY_NAME("family_name"),
    ORGANIZATION_NAME("organizationName"),
    ID_NUMMER("idNummer");

    private final String fieldname;

    CertificateExtractedFieldEnum(String fieldname) {
        this.fieldname = fieldname;
    }

    public String getFieldname() {
        return fieldname;
    }
}
