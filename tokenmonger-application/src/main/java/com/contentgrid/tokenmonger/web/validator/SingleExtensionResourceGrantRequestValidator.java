package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtension;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest.HasResource;
import com.contentgrid.tokenmonger.web.validator.SingleExtensionResourceGrantRequestValidator.ExtensionInformation;
import java.net.URI;
import java.util.HashSet;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class SingleExtensionResourceGrantRequestValidator<C extends ExtensionInformation> implements GrantRequestValidator<HasResource, C> {

    private final RegisteredExtensionRepository registeredExtensionRepository;

    @Override
    public String getDescription() {
        return "At least one 'resource' parameter must be present. All 'resource' parameters must be valid Extension URIs for one extension.";
    }

    @Override
    public void validate(HasResource grantRequest, C context) {
        var targetApps = new HashSet<RegisteredExtension>();

        for (URI resourceUri : grantRequest.getResource()) {
            var application = registeredExtensionRepository.findByResourceUri(resourceUri.toString())
                    .orElseThrow(() -> OAuth2ErrorBuilder.invalidRequest()
                            .parameter("resource", resourceUri.toString())
                            .description("is not registered for any extension")
                            .buildException());
            targetApps.add(application);
        }

        var targetApp = switch (targetApps.size()) {
            case 0 -> throw OAuth2ErrorBuilder.invalidRequest().parameter("resource").isRequired().buildException();
            case 1 -> targetApps.iterator().next();
            default -> throw OAuth2ErrorBuilder.invalidRequest().parameter("resource").description("must all be registered to the same extension").buildException();
        };
        context.setExtension(targetApp);
    }

    public interface ExtensionInformation {
        void setExtension(RegisteredExtension application);
        RegisteredExtension getExtension();
    }
}
