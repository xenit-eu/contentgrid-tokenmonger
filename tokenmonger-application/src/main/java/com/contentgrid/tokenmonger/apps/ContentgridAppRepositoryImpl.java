package com.contentgrid.tokenmonger.apps;

import com.contentgrid.configuration.api.ComposedConfiguration;
import com.contentgrid.configuration.api.lookup.ConcurrentLookup;
import com.contentgrid.configuration.api.lookup.Lookup;
import com.contentgrid.configuration.api.observable.Observable;
import com.contentgrid.configuration.api.observable.Observer;
import com.contentgrid.configuration.applications.ApplicationConfiguration;
import com.contentgrid.configuration.applications.ApplicationId;
import java.net.URI;
import java.util.Optional;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ContentgridAppRepositoryImpl implements ContentgridAppRepository, Observer<ComposedConfiguration<ApplicationId, ApplicationConfiguration>> {
    private final ConcurrentLookup<ApplicationId, ComposedConfiguration<ApplicationId, ApplicationConfiguration>> lookup = new ConcurrentLookup<>(ComposedConfiguration::getCompositionKey);
    private final Lookup<String, ComposedConfiguration<ApplicationId, ApplicationConfiguration>> byDomain = lookup.createMultiLookup(config -> config.getConfiguration().map(ApplicationConfiguration::getRoutingDomains).orElseGet(Set::of).stream());

    @Override
    public Optional<ContentgridApp> findByUri(URI uri) {
        var domain = uri.getHost();
        var configurations = byDomain.get(domain);
        return switch (configurations.size()) {
            case 0 -> Optional.empty();
            case 1 -> createApp(configurations.iterator().next());
            default -> {
                log.warn("Domain '{}' resolves to multiple applications; refusing to pick any.", domain);
                yield  Optional.empty();
            }
        };
        }

    private Optional<ContentgridApp> createApp(ComposedConfiguration<ApplicationId, ApplicationConfiguration> configuration) {
        return Optional.of(new ContentgridApp(
                configuration.getCompositionKey(),
                configuration.getConfiguration().map(ApplicationConfiguration::getRoutingDomains).orElseGet(Set::of)
        ));
    }

    @Override
    public void subscribe(Observable<ComposedConfiguration<ApplicationId, ApplicationConfiguration>> observable) {
        lookup.subscribe(observable);
    }
}
