package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.apps.ContentgridApp;
import com.contentgrid.tokenmonger.apps.ContentgridAppRepository;
import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest.HasResource;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator.ApplicationInformation;
import java.net.URI;
import java.util.HashSet;
import lombok.RequiredArgsConstructor;

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
                    .orElseThrow(() -> OAuth2ErrorBuilder.invalidRequest()
                            .parameter("resource", resourceUri.toString())
                            .description("is not registered for any application")
                            .buildException());
            targetApps.add(application);
        }

        var targetApp = switch (targetApps.size()) {
            case 0 -> throw OAuth2ErrorBuilder.invalidRequest().parameter("resource").isRequired().buildException();
            case 1 -> targetApps.iterator().next();
            default -> throw OAuth2ErrorBuilder.invalidRequest().parameter("resource").description("must all be registered to the same application").buildException();
        };
        context.setApplication(targetApp);
    }

    public interface ApplicationInformation {
        void setApplication(ContentgridApp application);
        ContentgridApp getApplication();
    }
}
