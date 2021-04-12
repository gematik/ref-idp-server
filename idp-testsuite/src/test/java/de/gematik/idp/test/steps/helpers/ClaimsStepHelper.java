package de.gematik.idp.test.steps.helpers;

import de.gematik.idp.test.steps.model.ClaimLocation;
import de.gematik.idp.test.steps.model.DateCompareMode;
import de.gematik.idp.test.steps.utils.SerenityReportUtils;
import de.gematik.test.bdd.Context;
import de.gematik.test.bdd.ContextKey;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Map;
import java.util.Set;
import net.thucydides.core.annotations.Step;
import org.apache.commons.collections.IteratorUtils;
import org.assertj.core.api.Assertions;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwx.Headers;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

public class ClaimsStepHelper {

    public JSONObject extractHeaderClaimsFromJWEString(final String token) throws JoseException {
        final JsonWebEncryption jsonWebEncryption = new JsonWebEncryption();
        jsonWebEncryption.setCompactSerialization(token);
        final Headers headers = jsonWebEncryption.getHeaders();
        return new JSONObject(JsonUtil.parseJson(headers.getFullHeaderAsJsonString()));
    }

    public JSONObject extractHeaderClaimsFromJWSString(final String token) throws JoseException {
        final JsonWebSignature jsonWebSignature = new JsonWebSignature();
        jsonWebSignature.setCompactSerialization(token);
        final Headers headers = jsonWebSignature.getHeaders();
        return new JSONObject(JsonUtil.parseJson(headers.getFullHeaderAsJsonString()));
    }

    @Step
    public void iExtractTheClaims(final ClaimLocation type) throws Throwable {
        extractClaimsFromString(type, Context.getCurrentResponse().getBody().asString(), false);
    }

    @Step
    public void iExtractTheClaimsFromResponseJsonField(final String jsonName, final ClaimLocation type)
        throws Throwable {
        final String jsoValue = new JSONObject(Context.getCurrentResponse().getBody().asString())
            .getString(jsonName);
        extractClaimsFromString(type, jsoValue, false);
    }

    @Step
    public void extractClaimsFromToken(final ClaimLocation cType, final String token)
        throws JoseException, InvalidJwtException, JSONException {
        if (Set.of(ContextKey.TOKEN_CODE_ENCRYPTED, ContextKey.SSO_TOKEN_ENCRYPTED).contains(token)) {
            extractClaimsFromString(cType, Context.get().get(token).toString(), true);
        } else {
            Assertions.assertThat(token)
                .isIn(ContextKey.TOKEN_CODE, ContextKey.SIGNED_CHALLENGE, ContextKey.ACCESS_TOKEN, ContextKey.ID_TOKEN);
            extractClaimsFromString(cType, Context.get().get(token).toString(), false);
        }
    }

    public void assertDateFromClaimMatches(final ClaimLocation claimLocation, final String claimName,
        final DateCompareMode compareMode,
        final Duration duration) throws JSONException {
        final JSONObject claims;
        final Map<String, Object> ctxt = Context.get().getMapForCurrentThread();
        if (claimLocation == ClaimLocation.body) {
            Assertions.assertThat(ctxt).containsKey(ContextKey.CLAIMS).doesNotContainEntry(ContextKey.CLAIMS, null);
            claims = (JSONObject) ctxt.get(ContextKey.CLAIMS);
        } else {
            Assertions.assertThat(ctxt).containsKey(ContextKey.HEADER_CLAIMS)
                .doesNotContainEntry(ContextKey.HEADER_CLAIMS, null);
            claims = (JSONObject) ctxt.get(ContextKey.HEADER_CLAIMS);
        }
        Assertions.assertThat(IteratorUtils.toArray(claims.keys())).contains(claimName);

        final ZonedDateTime d = ZonedDateTime
            .ofInstant(Instant.ofEpochSecond(claims.getLong(claimName)),
                ZoneId.of("UTC"));

        final ZonedDateTime expectedDate = ZonedDateTime
            .ofInstant(Instant.ofEpochMilli(System.currentTimeMillis()), ZoneId.of("UTC")).plus(duration);
        switch (compareMode) {
            case NOT_BEFORE:
                Assertions.assertThat(d).isAfterOrEqualTo(expectedDate);
                break;
            case AFTER:
                Assertions.assertThat(d).isAfter(expectedDate);
                break;
            case BEFORE:
                Assertions.assertThat(d).isBefore(expectedDate);
                break;
            case NOT_AFTER:
                Assertions.assertThat(d).isBeforeOrEqualTo(expectedDate);
                break;
        }
    }

    public JSONObject getClaims(final String jwt) throws InvalidJwtException {
        final JwtConsumerBuilder jwtConsBuilder = new JwtConsumerBuilder()
            .setSkipDefaultAudienceValidation()
            .setSkipSignatureVerification();
        return new JSONObject(jwtConsBuilder.build().process(jwt).getJwtClaims().getClaimsMap());
    }

    protected void extractClaimsFromString(final ClaimLocation cType, final String tokenAsCompactSerialization,
        final boolean jwe)
        throws InvalidJwtException, JSONException, JoseException {
        if (cType == ClaimLocation.body) {
            Context.get().put(ContextKey.CLAIMS, getClaims(tokenAsCompactSerialization));
            SerenityReportUtils
                .addCustomData("Body Claims", ((JSONObject) Context.get().get(ContextKey.CLAIMS)).toString(2));
        } else {
            final JSONObject json;
            if (jwe) {
                json = extractHeaderClaimsFromJWEString(tokenAsCompactSerialization);
            } else {
                json = extractHeaderClaimsFromJWSString(tokenAsCompactSerialization);
            }
            Context.get().put(ContextKey.HEADER_CLAIMS, json);
            SerenityReportUtils.addCustomData("Header Claims", json.toString(2));
        }
    }
}