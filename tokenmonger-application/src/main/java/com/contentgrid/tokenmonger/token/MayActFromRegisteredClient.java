package com.contentgrid.tokenmonger.token;

import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import java.net.URL;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@RequiredArgsConstructor
public class MayActFromRegisteredClient implements OAuth2TokenCustomizer<JwtEncodingContext> {
    private final URL extensionIssuer;
    private final RegisteredExtensionRepository extensionRepository;

    @Override
    public void customize(JwtEncodingContext context) {
        extensionRepository.findByClientId(context.getRegisteredClient().getClientId()).ifPresentOrElse(
                extension -> context.getClaims().claim("may_act", Map.of(
                        JwtClaimNames.ISS, extensionIssuer,
                        JwtClaimNames.SUB, extension.getExtensionId()
                )),
                () -> {
                    throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
                }
        );
    }
}
