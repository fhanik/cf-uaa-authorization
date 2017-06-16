package org.cloudfoundry.identity.authorize;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import org.cloudfoundry.identity.authorize.config.AccessLevel;
import org.cloudfoundry.identity.authorize.config.Client;
import org.cloudfoundry.identity.authorize.config.Endpoint;
import org.cloudfoundry.identity.authorize.config.Token;
import org.cloudfoundry.identity.authorize.config.TokenExposure;

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
