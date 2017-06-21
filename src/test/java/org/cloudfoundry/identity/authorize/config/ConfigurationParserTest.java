package org.cloudfoundry.identity.authorize.config;

import org.junit.Test;

import java.net.URI;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThat;

public class ConfigurationParserTest {

    public static final String TEST_YAML =
        "# both id_token and access_tokens are requested for all browser flows\n" +
        "default-access: authenticated-session\n" +
        "# default access requires authentication in form of a bearer token in session\n" +
        "# user token and authorize flow implied\n" +
        "# possible values:\n" +
        "#   - authenticated-session (token in session, browser login)\n" +
        "#   - authenticated-bearer  (bearer token required)\n" +
        "#   - insecure (all unlisted endpoints are not checked for security)\n" +
        "#   - deny-all (if the endpoint is not matched, deny all requests with 401)\n" +
        "endpoints:\n" +
        "  - pattern: /deposit/**\n" +
        "    browser: false\n" +
        "    scope:\n" +
        "      - user.deposit\n" +
        "      - user.admin\n" +
        "    user: true\n" +
        "    # API endpoint. Doesn't support browser flows, token required in each request\n" +
        "    # requires a user token with scope user.deposit\n" +
        "  - pattern: /health_check\n" +
        "    authenticated: false\n" +
        "    # API endpoint\n" +
        "    # No security\n" +
        "  - pattern: /account/**\n" +
        "    browser: true\n" +
        "    scope:\n" +
        "      - user.view\n" +
        "    # Browser endpoint that requires a session\n" +
        "    # User tokens is implied by browser: true\n" +
        "    # token still evaluated upon each request\n" +
        "    # because it is stored in the session\n" +
        "  - pattern: /admin/**\n" +
        "    user: false\n" +
        "    scope:\n" +
        "      - application.admin\n" +
        "    # Client token required in request\n" +
        "    # token must be supplied in request\n" +
        "    # browser: false is implied by user: false\n" +
        "uaa:\n" +
        "  uri: https://login.cf-system.domain.com\n" +
        "client:\n" +
        "  id: myapp_client\n" +
        "  secret: myapp_secret\n" +
        "  # these can be inherited from bound variables too\n" +
        "token:\n" +
        "  id: claims\n" +
        "  access: expose\n" +
        "  #expose claims only, not the actual token\n" +
        "  # we should also support setting the token as\n" +
        "  # bearer token so that existing spring app\n" +
        "  # just reads it as it if has not yet been validated.";

    @Test
    public void fromYaml() throws Exception {
        AuthorizationConfiguration configuration = new ConfigurationParser().fromYaml(TEST_YAML);
        assertNotNull(configuration);
        assertNotNull(configuration.getToken());
        assertSame(TokenExposure.CLAIMS, configuration.getToken().getIdToken());
        assertSame(TokenExposure.EXPOSE, configuration.getToken().getAccessToken());
        assertEquals(new URI("https://login.cf-system.domain.com"), configuration.getUaa());
        assertNotNull(configuration.getClient());
        assertEquals("myapp_client", configuration.getClient().getId());
        assertEquals("myapp_secret", configuration.getClient().getSecret());
        assertNotNull(configuration.getDefaultAccessLevel());
        assertSame(AccessLevel.AUTHENTICATED_SESSION, configuration.getDefaultAccessLevel());
        assertNotNull(configuration.getEndpoints());
        assertEquals(4, configuration.getEndpoints().size());

        //evaluate first endpoint
        evaluateEndpoint(configuration.getEndpoints().get(0), "/deposit**", true, false, true, "user.deposit", "user.admin");
        evaluateEndpoint(configuration.getEndpoints().get(1), "/health_check", false, false, false, new String[0]);
        evaluateEndpoint(configuration.getEndpoints().get(2), "/account/**", true, true, true, "user.view");
        evaluateEndpoint(configuration.getEndpoints().get(3), "/admin/**", true, false, false, "application.admin");
    }

    private void evaluateEndpoint(Endpoint ep,
                                  String pattern,
                                  boolean authenticated,
                                  boolean browser,
                                  boolean user,
                                  String... scopes) {
        assertEquals(pattern, ep.getPattern());
        String message = "Pattern=" + pattern + ": ";
        assertEquals(message, authenticated, ep.isAuthenticated());
        assertEquals(message, browser, ep.isBrowser());
        assertEquals(message, user, ep.isUser());
        assertEquals(message, scopes.length, ep.getScope().size());
        assertThat(message, ep.getScope(), containsInAnyOrder(scopes));
    }

}