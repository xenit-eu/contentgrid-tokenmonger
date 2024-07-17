package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.application.Application;
import com.contentgrid.tokenmonger.application.ApplicationRepository;
import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator.ApplicationInformation;
import java.net.URI;
import java.util.HashSet;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

@RequiredArgsConstructor
public class SingleApplicationResourceGrantRequestValidator<C extends ApplicationInformation> implements GrantRequestValidator<TokenExchangeGrantRequest, C> {

    private final ApplicationRepository applicationRepository;

    @Override
    public void validate(TokenExchangeGrantRequest grantRequest, C context) {
        var targetApps = new HashSet<Application>();

        for (URI resourceUri : grantRequest.getResource()) {
            var application = applicationRepository.findByUri(resourceUri)
                    .orElseThrow(() -> new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "No application found for 'resource' %s".formatted(resourceUri)));
            targetApps.add(application);
        }

        var targetApp = switch (targetApps.size()) {
            case 0 -> throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "At least one 'resource' must be requested");
            case 1 -> targetApps.iterator().next();
            default -> throw new OAuth2ErrorException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), "'resource' URIs can not map to different applications");
        };
        context.setApplication(targetApp);
        context.setApplicationResourcePaths(grantRequest.getResource().stream().map(this::extractPath).toList());
    }

    @SneakyThrows
    private String extractPath(URI uri) {
        return new URI(null, null, uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
    }

    public interface ApplicationInformation {
        void setApplication(Application application);
        Application getApplication();
        void setApplicationResourcePaths(List<String> paths);
        List<String> getApplicationResourcePaths();
    }
}
