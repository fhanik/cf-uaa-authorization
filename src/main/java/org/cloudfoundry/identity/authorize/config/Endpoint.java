package org.cloudfoundry.identity.authorize.config;

import java.util.Set;

import static java.util.Collections.emptySet;

public class Endpoint {
    private String pattern = "/**";
    private boolean browser = true;
    private Set<String> scope = emptySet();
    private boolean user = true;
    private boolean authenticated = true;


    public String getPattern() {
        return pattern;
    }

    public Endpoint setPattern(String pattern) {
        this.pattern = pattern;
        return this;
    }

    public boolean isBrowser() {
        return browser;
    }

    public Endpoint setBrowser(boolean browser) {
        this.browser = browser;
        return this;
    }

    public Set<String> getScope() {
        return scope;
    }

    public Endpoint setScope(Set<String> scope) {
        this.scope = scope;
        return this;
    }

    public boolean isUser() {
        return user;
    }

    public Endpoint setUser(boolean user) {
        this.user = user;
        return this;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public Endpoint setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
        return this;
    }
}
