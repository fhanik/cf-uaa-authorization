package org.cloudfoundry.identity.authorize;

import org.cloudfoundry.identity.authorize.config.AuthorizationConfiguration;
import org.cloudfoundry.identity.authorize.config.ConfigurationParser;
import org.cloudfoundry.identity.authorize.config.Endpoint;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public class UaaAuthorizationFilter implements javax.servlet.Filter {

    enum ContinueRequest {
        ALLOW,
        DENY
    }

    public static String PARAM = "authorization-yaml";
    private final UAA uaa;

    private AuthorizationConfiguration configuration;

    public UaaAuthorizationFilter(UAA uaa) {
        this.uaa = uaa;
    }

    public AuthorizationConfiguration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String yaml = filterConfig.getInitParameter(PARAM);
        configuration = new ConfigurationParser().fromYaml(yaml);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        ContinueRequest state = ContinueRequest.DENY;
        Endpoint endpoint = configuration.findEndpoint((HttpServletRequest) request);
        if (endpoint == null) {
            switch (configuration.getDefaultAccessLevel()) {
                case AUTHENTICATED_SESSION:
                    break;
                case AUTHENTICATED_BEARER:
                    break;
                case INSECURE:
                    state = ContinueRequest.ALLOW;
                    break;
                case DENY_ALL:
                    state = ContinueRequest.DENY;
                    break;
            }
        } else {
            if (!endpoint.isAuthenticated()) {
                state = ContinueRequest.ALLOW;
            }
        }

        if (state == ContinueRequest.ALLOW) {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void destroy() {

    }
}
