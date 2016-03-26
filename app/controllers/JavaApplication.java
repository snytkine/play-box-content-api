package controllers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ning.http.client.AsyncHttpClient;
import com.ning.http.client.RequestBuilder;
import org.slf4j.Logger;
import play.Configuration;
import play.cache.CacheApi;
import play.libs.F;
import play.libs.Json;
import play.libs.ws.WSClient;
import play.libs.ws.WSRequest;
import play.libs.ws.WSResponse;
import play.libs.ws.ning.NingWSResponse;
import play.mvc.*;

import javax.inject.Inject;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.ning.http.client.Response;
import com.ning.http.client.multipart.*;
import com.ning.http.client.AsyncCompletionHandler;


import play.twirl.api.Html;

public class JavaApplication extends Controller {
    private final Logger logger = org.slf4j.LoggerFactory.getLogger("application");

    private File file = new File(".", "README");
    private String redirectUri = "http://localhost:9000/authorize";

    private int expirationSeconds = 300; // 5 minutes

    private SecureRandom random = new SecureRandom();
    private Base64.Encoder encoder = java.util.Base64.getUrlEncoder();

    private final WSClient client;
    private final CacheApi cache;

    private final String clientId;
    private final String clientSecret;
    private final String boxLogin;

    @Inject
    public JavaApplication(WSClient client, CacheApi cache, Configuration config) {
        this.client = client;
        this.cache = cache;
        this.clientId = config.getString("client.id");
        this.clientSecret = config.getString("client.secret");
        this.boxLogin = config.getString("client.login");
    }

    public F.Promise<Result> index() throws NoSuchAlgorithmException {
        final String nonce = generateNonce(boxLogin);
        final String key = generateKey(nonce);

        // NOTE: the cache MUST be distributed here to keep track of the nonce
        cache.set(key, nonce, expirationSeconds);

        final WSRequest wsRequest = client.url("https://account.box.com/api/oauth2/authorize");
        wsRequest.setQueryParameter("response_type", "code");
        wsRequest.setQueryParameter( "client_id", clientId);
        wsRequest.setQueryParameter( "redirect_uri", redirectUri);
        wsRequest.setQueryParameter("state", nonce);
        wsRequest.setQueryParameter("box_login", boxLogin);
        final F.Promise<WSResponse> promise = wsRequest.get();
        return promise.map(result ->
            Results.ok(new Html(result.getBody()))
        );
    }

    public F.Promise<Result> authorize() throws NoSuchAlgorithmException {
        final Http.Request request = request();
        final String error = request.getQueryString("error");
        if (error != null) {
            final String errorDescription = request.getQueryString("error_description");
            return F.Promise.pure(
                Results.unauthorized(errorDescription)
            );
        } else {
            final String code = request.getQueryString("code");
            final String incomingNonce = request.getQueryString("state");
            final String key = generateKey(incomingNonce);
            if (cache.get(key) != null) {
                cache.remove(key);
                return validateAuthorization(code);
            } else {
                return F.Promise.pure(
                    Results.unauthorized("unknown")
                );
            }
        }
    }

    private F.Promise<Result> validateAuthorization(String code) {
        final WSRequest wsRequest = client.url("https://api.box.com/oauth2/token");
        wsRequest.setContentType("application/x-www-form-urlencoded");
        Map<String,String> params = new LinkedHashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret);
        final F.Promise<WSResponse> promise = wsRequest.post(encodeFormParameters(params));
        return promise.flatMap((WSResponse wsResponse) -> {
            if (wsResponse.getStatus() == 200) {
                final JsonNode jsonNode = wsResponse.asJson();
                JsonNode accessTokenResult = jsonNode.findValue("access_token");
                if (accessTokenResult != null) {
                    String accessToken = accessTokenResult.asText();
                    final F.Promise<WSResponse> responsePromise = uploadFile(accessToken, file);
                    return responsePromise.map(uploadResponse ->
                        Results.ok(uploadResponse.asJson()).as("application/json")
                    );
                } else {
                    logger.error("invalid user credentials");
                    return F.Promise.pure(Results.unauthorized("Invalid user credentials"));
                }
            } else {
                logger.error("Unexpected error " + wsResponse.getBody());
                return F.Promise.pure(Results.badRequest("unexpected error"));
            }
        });
    }

    private F.Promise<WSResponse> uploadFile(String accessToken, File file) {
        final FilePart filePart = new FilePart("filename", file);
        final String url = "https://upload.box.com/api/2.0/files/content";
        AsyncHttpClient ningClient = (AsyncHttpClient) client.getUnderlying();
        final RequestBuilder builder = new RequestBuilder("POST");

        final ObjectNode parentNode = Json.newObject();
        parentNode.put("id", "0");
        final ObjectNode data = Json.newObject();
        data.put("name", filePart.getFile().getName());
        data.set("parent", parentNode);
        final String attributes = Json.stringify(data);

        builder.setUrl(url);
        builder.addBodyPart(filePart);
        builder.addBodyPart(new StringPart("attributes", attributes));
        builder.setHeader("Authorization", "Bearer " + accessToken);
        builder.setHeader("Content-Type", "multipart/form-data");

        final F.RedeemablePromise<WSResponse> result = F.RedeemablePromise.empty();
        ningClient.executeRequest(builder.build(), new AsyncCompletionHandler<Response>() {
            @Override
            public Response onCompleted(Response response) throws Exception {
                result.success(new NingWSResponse(response));
                return response;
            }

            @Override
            public void onThrowable(Throwable t) {
                result.failure(t);
                super.onThrowable(t);
            }
        });
        return result;
    }

    private String encodeFormParameters(Map<String, String> params) {
        try {
            StringBuilder postData = new StringBuilder();
            for (Map.Entry<String, String> param : params.entrySet()) {
                if (postData.length() != 0) postData.append('&');
                postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
                postData.append('=');
                postData.append(URLEncoder.encode(String.valueOf(param.getValue()), "UTF-8"));
            }
            return postData.toString();
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("should never get here");
        }
    }

    private String generateKey(String nonce) throws NoSuchAlgorithmException {
        String key = clientId + "-" + nonce + "-" + redirectUri;
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(key.getBytes());
        return encoder.encodeToString(md.digest());
    }

    private String generateNonce(String login) {
        final byte[] buffer = new byte[16];
        random.nextBytes(buffer);
        final String u = encoder.encodeToString(login.getBytes(StandardCharsets.UTF_8));
        return encoder.encodeToString(buffer) + "-" + u;
    }

}
