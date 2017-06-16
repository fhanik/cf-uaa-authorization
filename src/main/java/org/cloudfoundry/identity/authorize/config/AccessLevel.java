package org.cloudfoundry.identity.authorize.config;

public enum AccessLevel {

    AUTHENTICATED_SESSION("authenticated-session"),
    AUTHENTICATED_BEARER("authenticated-bearer"),
    INSECURE("insecure"),
    DENY_ALL("deny-all");

    private String name;

    AccessLevel(String name) {
        this.name = name;
    }

    private String getName() {
        return name;
    }

    public static AccessLevel fromString(String s) {
        for (AccessLevel al : AccessLevel.values()) {
            if (al.getName().equals(s)) {
                return al;
            }
        }
        throw new IllegalArgumentException(s);
    }
}
