package com.contentgrid.tokenmonger.application;

import java.net.URI;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class InMemoryApplicationRepository implements ApplicationRepository {
    private final Map<String, Application> applicationsByDomain = new HashMap<>();

    public InMemoryApplicationRepository(Collection<Application> applications) {
        for (Application application : applications) {
            for (String applicationDomain : application.getDomains()) {
                applicationsByDomain.put(applicationDomain, application);
            }
        }
    }

    @Override
    public Optional<Application> findByUri(URI uri) {
        return Optional.ofNullable(applicationsByDomain.get(uri.getHost()));
    }

}
