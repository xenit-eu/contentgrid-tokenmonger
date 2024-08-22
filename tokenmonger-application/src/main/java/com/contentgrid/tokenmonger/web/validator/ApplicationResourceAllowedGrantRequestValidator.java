package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.error.OAuth2ErrorBuilder;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest.HasResource;
import com.contentgrid.tokenmonger.web.validator.ApplicationResourceAllowedGrantRequestValidator.ApplicationResourceInformation;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator.ApplicationInformation;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

@RequiredArgsConstructor
public class ApplicationResourceAllowedGrantRequestValidator<C extends ApplicationInformation & ApplicationResourceInformation> implements GrantRequestValidator<HasResource, C> {

    @Override
    public String getDescription() {
        return "All 'resource' parameters must be valid Application URIs for one application";
    }

    @Override
    public void validate(HasResource grantRequest, C context) {
        var allowedDomains = context.getApplication().getDomains();
        context.setApplicationResourcePaths(
                grantRequest.getResource()
                        .stream()
                        .map(resource -> extractPath(resource, allowedDomains))
                        .toList()
        );
    }

    @SneakyThrows
    private String extractPath(URI uri, Collection<String> allowedHosts) {
        if(!allowedHosts.contains(uri.getHost())) {
            throw OAuth2ErrorBuilder.invalidTarget()
                    .parameter(OAuth2ParameterNames.RESOURCE)
                    .description("is not an allowed host")
                    .buildException();
        }
        return new URI(null, null, uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
    }

    public interface ApplicationResourceInformation {
        void setApplicationResourcePaths(List<String> paths);
        List<String> getApplicationResourcePaths();
    }
}
