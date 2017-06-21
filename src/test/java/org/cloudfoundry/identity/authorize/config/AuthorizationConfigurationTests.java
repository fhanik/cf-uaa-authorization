package org.cloudfoundry.identity.authorize.config;

import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;

import static org.cloudfoundry.identity.authorize.config.ConfigurationParserTest.TEST_YAML;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

public class AuthorizationConfigurationTests {

    AuthorizationConfiguration configuration;
    HttpServletRequest request;

    @Before
    public void setup() {
        configuration = new ConfigurationParser().fromYaml(TEST_YAML);
        request = mock(HttpServletRequest.class);
    }

    @Test
    public void find_no_path() throws Exception {
        Endpoint ep = configuration.findEndpoint(request);
        assertNull(ep);
    }

    @Test
    public void find_deposit_endpoint() throws Exception {
        for (String path : Arrays.asList("/deposit", "/deposit/","/deposit/submit/test")) {
            reset(request);
            when(request.getPathInfo()).thenReturn(path);
            Endpoint ep = configuration.findEndpoint(request);
            assertNotNull("Testing path: "+path, ep);
            assertEquals("Testing path: "+path, "/deposit/**", ep.getPattern());
        }
    }



}