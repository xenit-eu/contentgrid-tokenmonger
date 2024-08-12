package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.apps.ContentgridApp;
import com.contentgrid.tokenmonger.apps.ContentgridAppRepository;
import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest.HasResource;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator.ApplicationInformation;
import java.net.URI;
import java.util.HashSet;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

@RequiredArgsConstructor
public class SingleApplicationResourceGrantRequestValidator<C extends ApplicationInformation> implements GrantRequestValidator<HasResource, C> {

    private final ContentgridAppRepository applicationRepository;

    @Override
    public String getDescription() {
        return "At least one 'resource' parameter must be present";
    }

    @Override
    public void validate(HasResource grantRequest, C context) {
        var targetApps = new HashSet<ContentgridApp>();

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
    }

    public interface ApplicationInformation {
        void setApplication(ContentgridApp application);
        ContentgridApp getApplication();
    }
}
