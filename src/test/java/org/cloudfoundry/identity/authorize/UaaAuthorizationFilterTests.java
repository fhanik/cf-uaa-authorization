package org.cloudfoundry.identity.authorize;

import org.cloudfoundry.identity.authorize.config.AccessLevel;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.cloudfoundry.identity.authorize.config.ConfigurationParserTest.TEST_YAML;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class UaaAuthorizationFilterTests {

    private UaaAuthorizationFilter filter;
    private FilterChain chain;
    private HttpServletResponse response;
    private HttpServletRequest request;
    private UAA uaa;

    @Before
    public void setup() throws Exception {
        FilterConfig config = Mockito.mock(FilterConfig.class);
        when(config.getInitParameter(UaaAuthorizationFilter.PARAM)).thenReturn(TEST_YAML);
        uaa = mock(UAA.class);
        filter = new UaaAuthorizationFilter(uaa);
        filter.init(config);
        chain = mock(FilterChain.class);
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
    }

    @Test
    public void test_init() throws Exception {
        assertNotNull(filter.getConfiguration());
    }

    @Test
    public void test_no_authentication() throws Exception {
        when(request.getPathInfo()).thenReturn("/health_check");
        filter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void default_session_auth() throws Exception {
        fail();
    }

    @Test
    public void default_deny_all() throws Exception {
        filter.getConfiguration().setDefaultAccessLevel(AccessLevel.DENY_ALL);
        when(request.getPathInfo()).thenReturn("/path_not_listed");
        assertNull(filter.getConfiguration().findEndpoint(request));
        filter.doFilter(request, response, chain);
        verify(chain, times(1)).doFilter(same(request), same(response));
    }

    @Test
    public void default_insecure() throws Exception {
        filter.getConfiguration().setDefaultAccessLevel(AccessLevel.INSECURE);
        when(request.getPathInfo()).thenReturn("/path_not_listed");
        assertNull(filter.getConfiguration().findEndpoint(request));
        filter.doFilter(request, response, chain);
        verifyZeroInteractions(chain);

    }

    @Test
    public void default_authentication_bearer() throws Exception {

    }


}