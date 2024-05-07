package com.contentgrid.tokenmonger.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.web.filter.OncePerRequestFilter;

@RequiredArgsConstructor
public class AuthorizationServerContextFilter extends OncePerRequestFilter {
    private final AuthorizationServerSettings serverSettings;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            var authorizationServerContext = new ServerSettingsAuthorizationServerContext(serverSettings);
            AuthorizationServerContextHolder.setContext(authorizationServerContext);
            filterChain.doFilter(request, response);
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }

    }

    private static class ServerSettingsAuthorizationServerContext implements AuthorizationServerContext {

        private final AuthorizationServerSettings serverSettings;

        public ServerSettingsAuthorizationServerContext(AuthorizationServerSettings serverSettings) {
            this.serverSettings = serverSettings;
        }

        @Override
        public String getIssuer() {
            return serverSettings.getIssuer();
        }

        @Override
        public AuthorizationServerSettings getAuthorizationServerSettings() {
            return serverSettings;
        }
    }
}
