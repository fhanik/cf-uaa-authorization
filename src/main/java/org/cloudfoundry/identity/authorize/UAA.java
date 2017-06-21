package org.cloudfoundry.identity.authorize;


import com.grack.nanojson.JsonParser;
import com.grack.nanojson.JsonParserException;
import org.apache.http.Header;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class UAA {

    private URI uri;
    private String clientId;
    private String clientSecret;

    public UAA(URI uri, String clientId, String clientSecret) {
        try {
            this.uri = new URI(uri.toASCIIString()+"/check_token");
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(uri.toASCIIString());
        }
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public Map<String, Object> validateToken(String token) throws IOException, URISyntaxException {
        try (CloseableHttpClient client = HttpClients.createDefault();) {
            HttpPost post = new HttpPost(uri);
            post.setHeader(getAuthorizationHeader());
            post.setHeader(new BasicHeader(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded"));
            post.setHeader(new BasicHeader(HttpHeaders.ACCEPT, "application/json"));
            List<NameValuePair> params = new LinkedList<>();
            params.add(new BasicNameValuePair("token", token));
            post.setEntity(new UrlEncodedFormEntity(params));
            CloseableHttpResponse response = client.execute(post);
            String body = readBody(response);
            int status = response.getStatusLine().getStatusCode();
            if (status == 200) {
                //success
                return (Map<String, Object>) JsonParser.any().from(body);
            } else if (status >= 400) {
                //failure
                throw new UaaAccessException(status, body);
            } else {
                throw new UaaAccessException(500, "Unrecognized status code:"+status);
            }
        } catch (JsonParserException e) {
            throw new UaaAccessException(500, "Unable to parse JSON data", e);
        }
    }

    protected Header getAuthorizationHeader() {
        String value = Base64.getEncoder().encodeToString(
            (clientId+":"+clientSecret).getBytes()
        );
        return new BasicHeader("Authorization", "Basic "+value);
    }

    protected String readBody(CloseableHttpResponse response) throws IOException {
        return EntityUtils.toString(response.getEntity());
    }

}
