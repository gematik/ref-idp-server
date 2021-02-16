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

import io.restassured.http.Cookie;
import io.restassured.http.Cookies;
import io.restassured.http.Headers;
import io.restassured.mapper.ObjectMapper;
import io.restassured.mapper.ObjectMapperType;
import io.restassured.mapper.TypeRef;
import io.restassured.path.json.JsonPath;
import io.restassured.path.json.config.JsonPathConfig;
import io.restassured.path.xml.XmlPath;
import io.restassured.path.xml.XmlPath.CompatibilityMode;
import io.restassured.path.xml.config.XmlPathConfig;
import io.restassured.response.Response;
import io.restassured.response.ResponseBody;
import io.restassured.response.ValidatableResponse;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Type;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.json.JSONException;

public class DiscoveryDocumentResponse implements Response {

    private final DiscoveryDocumentResponseBody body;

    public DiscoveryDocumentResponse(final File templateBody, final File templateHeader, final File privateKey)
        throws IOException, JSONException {
        body = new DiscoveryDocumentResponseBody(templateBody, templateHeader, privateKey);
    }

    @Override
    public String print() {
        return body.print();
    }

    @Override
    public String prettyPrint() {
        return body.prettyPrint();
    }

    @Override
    public Response peek() {
        return null;
    }

    @Override
    public Response prettyPeek() {
        return null;
    }

    @Override
    public <T> T as(final Class<T> cls) {
        return body.as(cls);
    }

    @Override
    public <T> T as(final Class<T> cls, final ObjectMapperType mapperType) {
        return body.as(cls, mapperType);
    }

    @Override
    public <T> T as(final Class<T> cls, final ObjectMapper mapper) {
        return body.as(cls, mapper);
    }

    @Override
    public <T> T as(final TypeRef<T> typeRef) {
        return body.as(typeRef);
    }

    @Override
    public <T> T as(final Type cls) {
        return body.as(cls);
    }

    @Override
    public <T> T as(final Type cls, final ObjectMapperType mapperType) {
        return body.as(cls, mapperType);
    }

    @Override
    public <T> T as(final Type cls, final ObjectMapper mapper) {
        return body.as(cls, mapper);
    }

    @Override
    public JsonPath jsonPath() {
        return body.jsonPath();
    }

    @Override
    public JsonPath jsonPath(final JsonPathConfig config) {
        return body.jsonPath(config);
    }

    @Override
    public XmlPath xmlPath() {
        return body.xmlPath();
    }

    @Override
    public XmlPath xmlPath(final XmlPathConfig config) {
        return body.xmlPath(config);
    }

    @Override
    public XmlPath xmlPath(final CompatibilityMode compatibilityMode) {
        return body.xmlPath(compatibilityMode);
    }

    @Override
    public XmlPath htmlPath() {
        return body.htmlPath();
    }

    @Override
    public <T> T path(final String path, final String... arguments) {
        return body.path(path, arguments);
    }

    @Override
    public String asString() {
        return body.asString();
    }

    @Override
    public byte[] asByteArray() {
        return body.asByteArray();
    }

    @Override
    public InputStream asInputStream() {
        return body.asInputStream();
    }

    @Override
    public Response andReturn() {
        return null;
    }

    @Override
    public Response thenReturn() {
        return null;
    }

    @Override
    public ResponseBody body() {
        return body;
    }

    @Override
    public ResponseBody getBody() {
        return body;
    }

    @Override
    public Headers headers() {
        return null;
    }

    @Override
    public Headers getHeaders() {
        return null;
    }

    @Override
    public String header(final String name) {
        return null;
    }

    @Override
    public String getHeader(final String name) {
        return null;
    }

    @Override
    public Map<String, String> cookies() {
        return null;
    }

    @Override
    public Cookies detailedCookies() {
        return null;
    }

    @Override
    public Map<String, String> getCookies() {
        return null;
    }

    @Override
    public Cookies getDetailedCookies() {
        return null;
    }

    @Override
    public String cookie(final String name) {
        return null;
    }

    @Override
    public String getCookie(final String name) {
        return null;
    }

    @Override
    public Cookie detailedCookie(final String name) {
        return null;
    }

    @Override
    public Cookie getDetailedCookie(final String name) {
        return null;
    }

    @Override
    public String contentType() {
        return "application/json";
    }

    @Override
    public String getContentType() {
        return "application/json";
    }

    @Override
    public String statusLine() {
        return null;
    }

    @Override
    public String getStatusLine() {
        return null;
    }

    @Override
    public String sessionId() {
        return null;
    }

    @Override
    public String getSessionId() {
        return null;
    }

    @Override
    public int statusCode() {
        return 200;
    }

    @Override
    public int getStatusCode() {
        return 200;
    }

    @Override
    public long time() {
        return 0;
    }

    @Override
    public long timeIn(final TimeUnit timeUnit) {
        return 0;
    }

    @Override
    public long getTime() {
        return 0;
    }

    @Override
    public long getTimeIn(final TimeUnit timeUnit) {
        return 0;
    }

    @Override
    public ValidatableResponse then() {
        return null;
    }
}
