package com.contentgrid.tokenmonger.configuration;

import java.net.URI;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.With;
import lombok.experimental.Accessors;
import lombok.experimental.FieldDefaults;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Accessors(fluent = true, chain = true)
@Setter
@FieldDefaults(level = AccessLevel.PRIVATE)
public class EndpointConfiguration {
    RequestMatcher baseMatcher = request -> true;

    @Getter
    URI issuer;

    String tokenEndpoint;
    String tokenIntrospectionEndpoint;
    String tokenRevocationEndpoint;

    String authorizationEndpoint;

    String jwkSetEndpoint;

    public interface Endpoint {
        String getPath();
        Optional<URI> getUri();
        RequestMatcher getMatcher();
    }

    @RequiredArgsConstructor(access = AccessLevel.PRIVATE)
    public class SimpleMethodEndpoint implements Endpoint {

        private final HttpMethod method;

        @NonNull
        private final Supplier<String> path;

        @With(value = AccessLevel.PRIVATE)
        private final RequestMatcher additionalMatcher;

        public SimpleMethodEndpoint(HttpMethod method, Supplier<String> path) {
            this(method, path, request -> true);
        }

        @Override
        public String getPath() {
            return path.get();
        }

        @Override
        public Optional<URI> getUri() {
            return Optional.ofNullable(getPath()).map(issuer::resolve);
        }

        @Override
        public RequestMatcher getMatcher() {
            return new DeferredRequestMatcher(() -> new AndRequestMatcher(
                    baseMatcher,
                    additionalMatcher,
                    new AntPathRequestMatcher(
                            getPath(),
                            Optional.ofNullable(this.method).map(HttpMethod::name).orElse(null)
                    )
            ));
        }
    }

    public Endpoint getTokenEndpoint() {
        return new SimpleMethodEndpoint(HttpMethod.POST, () -> this.tokenEndpoint);
    }

    public Endpoint getTokenIntrospectionEndpoint() {
        return new SimpleMethodEndpoint(HttpMethod.POST, () -> this.tokenIntrospectionEndpoint);
    }

    public Endpoint getTokenRevocationEndpoint() {
        return new SimpleMethodEndpoint(HttpMethod.POST, () -> this.tokenRevocationEndpoint);
    }

    public Endpoint getAuthorizationEndpoint() {
        return new SimpleMethodEndpoint(null, () -> authorizationEndpoint);
    }

    public Endpoint getJwkSetEndpoint() {
        return new SimpleMethodEndpoint(HttpMethod.GET, () -> this.jwkSetEndpoint);
    }

    public Endpoint getAuthorizationServerMetadataEndpoint() {
        return new SimpleMethodEndpoint(HttpMethod.GET, () -> {
            return "/.well-known/oauth-authorization-server"+issuer.getPath();
        }).withAdditionalMatcher(new DeferredRequestMatcher(() -> new RequestHeaderRequestMatcher("Host", issuer.getAuthority())));
    }

    private Stream<Endpoint> enabledEndpoints() {
        var builder = Stream.<Endpoint>builder();

        if(this.issuer != null) {
            builder.add(this.getAuthorizationServerMetadataEndpoint());
        }

        if(this.tokenEndpoint != null) {
            builder.add(this.getTokenEndpoint());
        }
        if(this.tokenIntrospectionEndpoint != null) {
            builder.add(this.getTokenIntrospectionEndpoint());
        }
        if(this.tokenRevocationEndpoint != null) {
            builder.add(this.getTokenIntrospectionEndpoint());
        }
        if(this.authorizationEndpoint != null) {
            builder.add(this.getAuthorizationEndpoint());
        }

        if(this.jwkSetEndpoint != null) {
            builder.add(getJwkSetEndpoint());
        }

        return builder.build();
    }

    public RequestMatcher getRequestMatcher() {
        return new DeferredRequestMatcher(() -> new OrRequestMatcher(
                enabledEndpoints().map(Endpoint::getMatcher).toList()
        ));
    }

}

