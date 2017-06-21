package org.cloudfoundry.identity.authorize;

import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;

public class UAATests {

    private static final String HTTP_LOCALHOST_8080_UAA = "http://localhost:8080/uaa";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private UAA uaa;
    private String clientId;
    private String secret;

    @Before
    public void setup() throws Exception {
        clientId = "oauth_showcase_client_credentials";
        secret = "secret";
        uaa = new UAA(new URI(HTTP_LOCALHOST_8080_UAA), clientId, secret);
    }

    @Test
    public void validateToken() throws Exception {
        String accessToken = getToken();
        Map<String, Object> tokenClaims = uaa.validateToken(accessToken);
        assertEquals(clientId, tokenClaims.get("sub"));
        assertEquals(HTTP_LOCALHOST_8080_UAA+"/oauth/token", tokenClaims.get("iss"));
    }

    @Test
    public void invalid_token() throws Exception {
        exception.expect(UaaAccessException.class);
        uaa.validateToken("invalid");
    }


    public String getToken() throws Exception {
        try (CloseableHttpClient client = HttpClients.createDefault();) {
            HttpPost post = new HttpPost(HTTP_LOCALHOST_8080_UAA + "/oauth/token");
            post.setHeader(uaa.getAuthorizationHeader());
            post.setHeader(new BasicHeader(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded"));
            post.setHeader(new BasicHeader(HttpHeaders.ACCEPT, "application/json"));
            List<NameValuePair> params = new LinkedList<>();
            params.add(new BasicNameValuePair("grant_type", "client_credentials"));
            post.setEntity(new UrlEncodedFormEntity(params));
            CloseableHttpResponse response = client.execute(post);
            String body = uaa.readBody(response);
            int status = response.getStatusLine().getStatusCode();
            if (status == 200) {
                //success
                Map<String, Object> map = (Map<String, Object>) JsonParser.any().from(body);
                return (String) map.get("access_token");
            } else {
                //failure
                throw new UaaAccessException(status, body);
            }
        } catch (JsonParserException e) {
            throw new UaaAccessException(500, "Unable to parse JSON data", e);
        }
    }

}