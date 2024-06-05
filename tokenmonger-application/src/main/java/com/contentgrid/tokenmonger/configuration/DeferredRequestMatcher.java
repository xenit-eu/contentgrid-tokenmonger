package com.contentgrid.tokenmonger.configuration;

import jakarta.servlet.http.HttpServletRequest;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.matcher.RequestMatcher;

@RequiredArgsConstructor
public class DeferredRequestMatcher implements RequestMatcher {
    private final Supplier<RequestMatcher> matcherSupplier;

    @Override
    public boolean matches(HttpServletRequest request) {
        return matcherSupplier.get().matches(request);
    }

}
