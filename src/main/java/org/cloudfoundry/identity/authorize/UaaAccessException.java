package org.cloudfoundry.identity.authorize;


public class UaaAccessException extends RuntimeException {

    private int httpStatus;

    public UaaAccessException(int httpStatus, String message) {
        super(message);
        this.httpStatus = httpStatus;
    }

    public UaaAccessException(int httpStatus, String message, Throwable cause) {
        super(message, cause);
        this.httpStatus = httpStatus;
    }

    public int getHttpStatus() {
        return httpStatus;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("UaaAccessException{");
        sb.append("httpStatus=").append(getHttpStatus());
        sb.append("; message=").append(getMessage());
        sb.append('}');
        return sb.toString();
    }
}
