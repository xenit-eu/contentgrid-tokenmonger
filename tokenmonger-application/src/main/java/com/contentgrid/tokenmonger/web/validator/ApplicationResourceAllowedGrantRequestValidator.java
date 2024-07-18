package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.OAuth2ErrorException;
import com.contentgrid.tokenmonger.oauth2.grants.GrantRequest.HasResource;
import com.contentgrid.tokenmonger.web.validator.ApplicationResourceAllowedGrantRequestValidator.ApplicationResourceInformation;
import com.contentgrid.tokenmonger.web.validator.SingleApplicationResourceGrantRequestValidator.ApplicationInformation;
import java.net.URI;
import java.util.Collection;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.oauth2.core.OAuth2Error;

@RequiredArgsConstructor
public class ApplicationResourceAllowedGrantRequestValidator<C extends ApplicationInformation & ApplicationResourceInformation> implements GrantRequestValidator<HasResource, C> {

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
            throw new OAuth2ErrorException(new OAuth2Error(
                    "invalid_target",
                    "Requested resource is not an allowed host (%s)".formatted(String.join(",", allowedHosts)),
                    "https://www.rfc-editor.org/rfc/rfc8707.html#section-2"
            ));
        }
        return new URI(null, null, uri.getPath(), uri.getQuery(), uri.getFragment()).toString();
    }

    public interface ApplicationResourceInformation {
        void setApplicationResourcePaths(List<String> paths);
        List<String> getApplicationResourcePaths();
    }
}
