package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtension;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.web.validator.SingleExtensionResourceGrantRequestValidator.ExtensionInformation;
import java.net.URI;
import java.util.HashSet;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

@RequiredArgsConstructor
public class SingleExtensionResourceGrantRequestValidator<C extends ExtensionInformation> implements GrantRequestValidator<TokenExchangeGrantRequest, C> {

    private final RegisteredExtensionRepository registeredExtensionRepository;

    @Override
    public void validate(TokenExchangeGrantRequest grantRequest, C context) {
        var targetApps = new HashSet<RegisteredExtension>();

        for (URI resourceUri : grantRequest.getResource()) {
            var application = registeredExtensionRepository.findByResourceUri(resourceUri.toString())
                    .orElseThrow(() -> new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "No application found for 'resource' %s".formatted(resourceUri)));
            targetApps.add(application);
        }

        var targetApp = switch (targetApps.size()) {
            case 0 -> throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "At least one 'resource' must be requested");
            case 1 -> targetApps.iterator().next();
            default -> throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "'resource' URIs can not map to different applications");
        };
        context.setExtension(targetApp);
    }

    @SneakyThrows
    private String extractPath(URI uri) {
        return new URI(null, null, uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
    }

    public interface ExtensionInformation {
        void setExtension(RegisteredExtension application);
        RegisteredExtension getExtension();
    }
}
