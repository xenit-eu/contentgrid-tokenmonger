package com.contentgrid.tokenmonger.web.mapping;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.servlet.mvc.condition.AbstractRequestCondition;

/**
 * Request condition based on the <code>Host</code> HTTP header
 */
@RequiredArgsConstructor
public class HostRequestCondition extends AbstractRequestCondition<HostRequestCondition> implements
        RequestMatcher {

    @NonNull
    private final Set<String> hosts;

    @Override
    protected Collection<?> getContent() {
        return hosts;
    }

    @Override
    protected String getToStringInfix() {
        return " || ";
    }

    @Override
    public HostRequestCondition combine(HostRequestCondition other) {
        var newHosts = new HashSet<>(hosts);
        newHosts.addAll(other.hosts);
        return new HostRequestCondition(newHosts);
    }

    @Override
    public HostRequestCondition getMatchingCondition(HttpServletRequest request) {
        var requestUri = URI.create(request.getRequestURL().toString());
        if (hosts.contains(requestUri.getHost())) {
            return new HostRequestCondition(Set.of(requestUri.getHost()));
        } else if (hosts.isEmpty()) {
            return this;
        }
        return null;
    }

    @Override
    public int compareTo(HostRequestCondition other, HttpServletRequest request) {
        if (other.hosts.size() != this.hosts.size()) {
            return other.hosts.size() - this.hosts.size();
        }

        if (this.hosts.size() == 1) {
            return this.hosts.iterator().next().compareTo(other.hosts.iterator().next());
        }

        return 0;
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        return getMatchingCondition(request) != null;
    }
}
