package org.cloudfoundry.identity.authorize.config;

import org.cloudfoundry.identity.authorize.util.AntPathMatcher;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import static java.util.Collections.emptyList;
import static org.cloudfoundry.identity.authorize.config.TokenExposure.EXPOSE;

public class AuthorizationConfiguration {

    private AccessLevel defaultAccessLevel = AccessLevel.DENY_ALL;
    private URI uaa;
    private List<Endpoint> endpoints = emptyList();
    private Client client;
    private Token token = new Token(TokenExposure.CLAIMS, EXPOSE);

    public URI getUaa() {
        return uaa;
    }

    public void setUaa(String uaa) {
        try {
            setUaa(new URI(uaa));
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(uaa, e);
        }
    }

    public Endpoint findEndpoint(HttpServletRequest request) {
        AntPathMatcher matcher = new AntPathMatcher();
        String pathInfo = request.getPathInfo();
        if (pathInfo==null || pathInfo.trim().length()==0) {
            pathInfo = "/";
        }
        for (Endpoint ep : endpoints) {
            if (matcher.match(ep.getPattern(), pathInfo)) {
                return ep;
            }
        }
        return null;
    }


    public void setUaa(URI uaa) {
        this.uaa = uaa;
    }

    public List<Endpoint> getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(List<Endpoint> endpoints) {
        this.endpoints = endpoints;
    }

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    public Token getToken() {
        return token;
    }

    public void setToken(Token token) {
        this.token = token;
    }

    public AccessLevel getDefaultAccessLevel() {
        return defaultAccessLevel;
    }

    public void setDefaultAccessLevel(AccessLevel defaultAccessLevel) {
        this.defaultAccessLevel = defaultAccessLevel;
    }
}
