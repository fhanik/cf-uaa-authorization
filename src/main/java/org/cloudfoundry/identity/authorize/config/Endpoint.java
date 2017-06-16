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

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public boolean isBrowser() {
        return browser;
    }

    public void setBrowser(boolean browser) {
        this.browser = browser;
    }

    public Set<String> getScope() {
        return scope;
    }

    public void setScope(Set<String> scope) {
        this.scope = scope;
    }

    public boolean isUser() {
        return user;
    }

    public void setUser(boolean user) {
        this.user = user;
    }

    public boolean isAuthenticated() {
        return authenticated;
    }

    public void setAuthenticated(boolean authenticated) {
        this.authenticated = authenticated;
    }
}
