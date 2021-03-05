/*
 * Copyright (c) 2021 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.idp.test.steps.model;

import de.gematik.idp.authentication.IdpJwtProcessor;
import de.gematik.idp.crypto.CryptoLoader;
import de.gematik.idp.crypto.model.PkiIdentity;
import io.restassured.mapper.ObjectMapper;
import io.restassured.mapper.ObjectMapperType;
import io.restassured.mapper.TypeRef;
import io.restassured.path.json.JsonPath;
import io.restassured.path.json.config.JsonPathConfig;
import io.restassured.path.xml.XmlPath;
import io.restassured.path.xml.XmlPath.CompatibilityMode;
import io.restassured.path.xml.config.XmlPathConfig;
import io.restassured.response.ResponseBody;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.time.ZonedDateTime;
import java.util.HashMap;
import java.util.Map;
import lombok.SneakyThrows;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.assertj.core.api.Assertions;
import org.json.JSONException;
import org.json.JSONObject;

public class DiscoveryDocumentResponseBody implements ResponseBody {

    JSONObject jsonBody;
    JSONObject jsonHeader;

    String signedContent;

    @SneakyThrows
    public DiscoveryDocumentResponseBody(final File templateBody, final File templateHeader, final File privateKey)
        throws IOException, JSONException {
        jsonBody = new JSONObject(IOUtils.toString(new FileReader(templateBody, StandardCharsets.UTF_8)));

        final ZonedDateTime now = ZonedDateTime.now();
        jsonBody.put("exp", now.plusHours(24).toEpochSecond());
        jsonBody.put("iat", now.toEpochSecond());

        jsonHeader = new JSONObject(IOUtils.toString(new FileReader(templateHeader, StandardCharsets.UTF_8)));

        String keyPwd = System.getenv("IDP_LOCAL_DISCDOC_PKEY_PWD");
        if (keyPwd == null) {
            keyPwd = "00";
        }
        final byte[] p12FileContent = FileUtils
            .readFileToByteArray(privateKey);
        final PkiIdentity pkiId = CryptoLoader.getIdentityFromP12(p12FileContent, keyPwd);
        final IdpJwtProcessor jwtProcessor = new IdpJwtProcessor(pkiId);
        final Map<String, Object> headers = new HashMap<>();
        jsonHeader.keys().forEachRemaining(key -> {
            try {
                headers.put(key.toString(), jsonHeader.get(key.toString()).toString());
            } catch (final JSONException e) {
                Assertions.fail("Unable to convert headers for discovery document", e);
            }
        });
        signedContent = jwtProcessor
            .buildJws(jsonBody.toString(), headers, false)
            .getRawString();
    }

    @Override
    public String print() {
        return signedContent;
    }

    @SneakyThrows
    @Override
    public String prettyPrint() {
        return signedContent;
    }

    @Override
    public ResponseBody peek() {
        return null;
    }

    @Override
    public ResponseBody prettyPeek() {
        return null;
    }

    @Override
    public <T> T as(final Class<T> cls) {
        return null;
    }

    @Override
    public <T> T as(final Class<T> cls, final ObjectMapperType mapperType) {
        return null;
    }

    @Override
    public <T> T as(final Class<T> cls, final ObjectMapper mapper) {
        return null;
    }

    @Override
    public <T> T as(final TypeRef<T> typeRef) {
        return null;
    }

    @Override
    public <T> T as(final Type cls) {
        return null;
    }

    @Override
    public <T> T as(final Type cls, final ObjectMapperType mapperType) {
        return null;
    }

    @Override
    public <T> T as(final Type cls, final ObjectMapper mapper) {
        return null;
    }

    @Override
    public JsonPath jsonPath() {
        return null;
    }

    @Override
    public JsonPath jsonPath(final JsonPathConfig config) {
        return null;
    }

    @Override
    public XmlPath xmlPath() {
        return null;
    }

    @Override
    public XmlPath xmlPath(final XmlPathConfig config) {
        return null;
    }

    @Override
    public XmlPath xmlPath(final CompatibilityMode compatibilityMode) {
        return null;
    }

    @Override
    public XmlPath htmlPath() {
        return null;
    }

    @Override
    public <T> T path(final String path, final String... arguments) {
        return null;
    }

    @Override
    public String asString() {
        return signedContent;
    }

    @Override
    public byte[] asByteArray() {
        return null;
    }

    @Override
    public InputStream asInputStream() {
        return null;
    }
}
