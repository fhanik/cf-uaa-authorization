package org.cloudfoundry.identity.authorize.config;

public class Token {

    private TokenExposure idToken;
    private TokenExposure accessToken;

    public Token(TokenExposure idToken, TokenExposure accessToken) {
        this.idToken = idToken;
        this.accessToken = accessToken;
    }

    public TokenExposure getIdToken() {
        return idToken;
    }

    public void setIdToken(TokenExposure idToken) {
        this.idToken = idToken;
    }

    public TokenExposure getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(TokenExposure accessToken) {
        this.accessToken = accessToken;
    }
}
