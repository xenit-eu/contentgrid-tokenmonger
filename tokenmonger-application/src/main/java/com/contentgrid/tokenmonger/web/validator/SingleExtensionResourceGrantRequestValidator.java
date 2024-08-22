package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtension;
import com.contentgrid.tokenmonger.extensions.registration.RegisteredExtensionRepository;
import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest.HasResource;
import com.contentgrid.tokenmonger.web.validator.SingleExtensionResourceGrantRequestValidator.ExtensionInformation;
import java.net.URI;
import java.util.HashSet;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

@RequiredArgsConstructor
public class SingleExtensionResourceGrantRequestValidator<C extends ExtensionInformation> implements GrantRequestValidator<HasResource, C> {

    private final RegisteredExtensionRepository registeredExtensionRepository;

    @Override
    public String getDescription() {
        return "At least one 'resource' parameter must be present. All 'resource' parameters must be valid Extension URIs for one extension.";
    }

    @Override
    public void validate(HasResource grantRequest, C context) {
        var errorBuilder = OAuth2ErrorBuilder.invalidRequest()
                .parameter(OAuth2ParameterNames.RESOURCE);
        var targetExtensions = new HashSet<RegisteredExtension>();

        for (URI resourceUri : grantRequest.getResource()) {
            var extension = registeredExtensionRepository.findByResourceUri(resourceUri.toString())
                    .orElseThrow(() -> OAuth2ErrorBuilder.invalidRequest()
                            .parameter(OAuth2ParameterNames.RESOURCE, resourceUri.toString())
                            .description("is not registered for any extension")
                            .buildException());
            targetExtensions.add(extension);
        }

        var targetExtension = switch (targetExtensions.size()) {
            case 0 -> throw errorBuilder.isRequired().buildException();
            case 1 -> targetExtensions.iterator().next();
            default -> throw errorBuilder.allValues("registered to the same extension").buildException();
        };
        context.setExtension(targetExtension);
    }

    public interface ExtensionInformation {
        void setExtension(RegisteredExtension application);
        RegisteredExtension getExtension();
    }
}
