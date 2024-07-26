package com.contentgrid.tokenmonger.web.mapping;

import com.contentgrid.tokenmonger.IssuerContext;
import com.contentgrid.tokenmonger.oauth2.OAuth2ServerConfiguration;
import java.lang.reflect.Method;
import java.net.URI;
import java.util.Objects;
import java.util.Set;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * Custom request mapping that prefixes/suffixes {@link org.springframework.web.bind.annotation.RequestMapping}
 * controller annotations with the issuer URI set for an {@link IssuerContext}
 *
 * It allows for dynamic definitions of the controller endpoints, based on configuration of the issuer uris in the application properties.
 * It also ensures that requests come from the same host as the configured issuer URI
 */
public class TokenmongerRequestMappingHandlerMapping extends RequestMappingHandlerMapping {

    @Override
    protected RequestMappingInfo getMappingForMethod(Method method, Class<?> handlerType) {
        var parentMapping = super.getMappingForMethod(method, handlerType);
        if(parentMapping == null) {
            return null;
        }

        var issuerMapping = createIssuerContextMapping(handlerType);

        if(issuerMapping == null) {
            return parentMapping;
        }

        var issuerMappingConfiguration = AnnotatedElementUtils.getMergedAnnotation(method, IssuerContextCombinationMapping.class);

        if(issuerMappingConfiguration == null) {
            throw new IllegalStateException("An @%s annotation is required when using the @%s annotation".formatted(
                    IssuerContextCombinationMapping.class.getName(),
                    IssuerContext.class.getName()
            ));
        }

        return switch(issuerMappingConfiguration.value()) {
            case PREPEND -> issuerMapping.combine(parentMapping);
            case APPEND -> parentMapping.combine(issuerMapping);
            case IGNORE -> parentMapping;
        };
    }

    private RequestMappingInfo createIssuerContextMapping(Class<?> handlerType) {
        var issuerContext = AnnotatedElementUtils.findMergedAnnotation(handlerType, IssuerContext.class);
        if(issuerContext == null) {
            return null;
        }
        var oauthServerConfiguration = findConfigurationForAnnotation(issuerContext);
        if(oauthServerConfiguration == null) {
            throw new IllegalStateException("An %s with qualifier %s(%s) is required".formatted(OAuth2ServerConfiguration.class.getName(), IssuerContext.class.getName(), issuerContext.value()));
        }

        var issuerUri = URI.create(oauthServerConfiguration.getIssuer());

        return RequestMappingInfo.paths(issuerUri.getPath())
                .customCondition(new HostRequestCondition(Set.of(issuerUri.getHost())))
                .build();
    }

    private OAuth2ServerConfiguration findConfigurationForAnnotation(IssuerContext issuerContext) {
        var applicationContext = obtainApplicationContext();
        for (String beanName : applicationContext.getBeanNamesForType(OAuth2ServerConfiguration.class)) {
            var beanIssuerContextAnnotation = applicationContext.findAnnotationOnBean(beanName, IssuerContext.class);
            if(beanIssuerContextAnnotation != null && Objects.equals(beanIssuerContextAnnotation.value(), issuerContext.value())) {
                return applicationContext.getBean(beanName, OAuth2ServerConfiguration.class);
            }
        }
        return null;
    }

}
