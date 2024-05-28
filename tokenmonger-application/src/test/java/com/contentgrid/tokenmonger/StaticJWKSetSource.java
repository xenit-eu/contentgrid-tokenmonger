package com.contentgrid.tokenmonger;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSetCacheRefreshEvaluator;
import com.nimbusds.jose.jwk.source.JWKSetSource;
import com.nimbusds.jose.proc.SecurityContext;

class StaticJWKSetSource implements JWKSetSource<SecurityContext> {

    private final JWKSet staticJWKSet;

    public StaticJWKSetSource(JWKSet staticJWKSet) {
        this.staticJWKSet = staticJWKSet;
    }

    @Override
    public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime,
            SecurityContext context) {
        return staticJWKSet;
    }

    @Override
    public void close() {

    }
}
