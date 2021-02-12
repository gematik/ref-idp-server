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
import org.json.JSONException;
import org.json.JSONObject;

public class DiscoveryDocumentResponseBody implements ResponseBody {

    JSONObject jsonContent;

    String signedContent;

    public DiscoveryDocumentResponseBody(final File template, final String certFile)
        throws IOException, JSONException {
        jsonContent = new JSONObject(IOUtils.toString(new FileReader(template, StandardCharsets.UTF_8)));

        final ZonedDateTime now = ZonedDateTime.now();
        jsonContent.put("nbf", now.toEpochSecond());
        jsonContent.put("exp", now.plusHours(24).toEpochSecond());
        jsonContent.put("iat", now.toEpochSecond());
        final byte[] p12FileContent = FileUtils
            .readFileToByteArray(new File("src/test/resources/" + certFile));

        final PkiIdentity pkiId = CryptoLoader.getIdentityFromP12(p12FileContent, "00");
        final IdpJwtProcessor jwtProcessor = new IdpJwtProcessor(pkiId);
        final Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "BP256R1");
        signedContent = jwtProcessor
            .buildJws(jsonContent.toString(), headers, false)
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
