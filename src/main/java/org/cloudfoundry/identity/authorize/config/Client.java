package org.cloudfoundry.identity.authorize.config;

public class Client {

    private String id;
    private String secret;

    public Client(String id, String secret) {
        this.id = id;
        this.secret = secret;
    }

    public String getId() {
        return id;
    }

    public String getSecret() {
        return secret;
    }
}
