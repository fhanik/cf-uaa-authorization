package org.cloudfoundry.identity.authorize;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.cloudfoundry.identity.authorize.config.AccessLevel;
import org.cloudfoundry.identity.authorize.config.Client;
import org.cloudfoundry.identity.authorize.config.Endpoint;
import org.cloudfoundry.identity.authorize.config.Token;
import org.cloudfoundry.identity.authorize.config.TokenExposure;
import org.yaml.snakeyaml.Yaml;

import static java.util.Collections.emptySet;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.authorize.config.AccessLevel.INSECURE;
import static org.cloudfoundry.identity.authorize.config.TokenExposure.fromString;

public class UaaAuthorizationFilter implements javax.servlet.Filter {

    public static String PARAM = "authorization-yaml";

    private AuthorizationConfiguration configuration;

    public AuthorizationConfiguration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String yaml = filterConfig.getInitParameter(PARAM);
        Map<String, Object> load = (Map<String, Object>) new Yaml().load(yaml);
        configuration = new AuthorizationConfiguration();

        if (load.get("token")!=null) {
            Map<String, String> token = (Map<String, String>) load.get("token");
            Token t = new Token(
                fromString(ofNullable(token.get("id")).orElse(TokenExposure.CLAIMS.getName())),
                fromString(ofNullable(token.get("access")).orElse(TokenExposure.EXPOSE.getName()))
            );
            configuration.setToken(t);
        }

        Map<String,Object> uaa = (Map<String, Object>) load.get("uaa");
        configuration.setUaa((String) uaa.get("uri"));

        if (load.get("default-access")!=null) {
            String access = (String) load.get("default-access");
            configuration.setDefaultAccessLevel(AccessLevel.fromString(access));
        }

        if (load.get("client")!=null) {
            Map<String, String> client = (Map<String, String>) load.get("client");
            Client c = new Client(
                client.get("id"),
                client.get("secret")
            );
            configuration.setClient(c);
        }

        if (load.get("endpoints")!=null) {
            Collection<Map<String,Object>> eps = (Collection<Map<String, Object>>) load.get("endpoints");
            Set<Endpoint> endpoints = new LinkedHashSet<>(eps.size());
            for (Map<String,Object> ep : eps) {
                Endpoint endpoint = new Endpoint();
                endpoint.setPattern((String) ep.get("pattern"));
                boolean authenticated = ofNullable((Boolean)ep.get("authenticated")).orElse(configuration.getDefaultAccessLevel() != INSECURE);
                endpoint.setAuthenticated(authenticated);
                if (authenticated) {
                    boolean user = ofNullable((Boolean) ep.get("user")).orElse(true);
                    endpoint.setUser(user);
                    if (!user) {
                        endpoint.setBrowser(false);
                    } else {
                        boolean browser = ofNullable((Boolean) ep.get("browser")).orElse(true);
                        endpoint.setBrowser(browser);
                    }
                    endpoint.setScope(new HashSet((Collection) ep.get("scope")));
                } else {
                    endpoint.setBrowser(false);
                    endpoint.setUser(false);
                    endpoint.setScope(emptySet());
                }
                endpoints.add(endpoint);
            }
            configuration.setEndpoints(new LinkedList(endpoints));
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

    }

    @Override
    public void destroy() {

    }
}
