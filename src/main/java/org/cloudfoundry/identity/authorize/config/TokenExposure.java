package org.cloudfoundry.identity.authorize.config;

public enum TokenExposure {

    CLAIMS("claims"),
    EXPOSE("expose");


    private String name;

    TokenExposure(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static TokenExposure fromString(String s) {
        for (TokenExposure te : TokenExposure.values()) {
            if (te.getName().equals(s)) {
                return te;
            }
        }
        throw new IllegalArgumentException(s);
    }
}
