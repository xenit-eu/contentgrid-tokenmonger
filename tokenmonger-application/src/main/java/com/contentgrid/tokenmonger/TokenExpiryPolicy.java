package com.contentgrid.tokenmonger;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.stream.Stream;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class TokenExpiryPolicy {
    private final Duration maximumExpirationTime;
    private final Clock clock;

    public @NonNull Instant getExpiry(Instant ...expiryTimes) {
        return Stream.concat(
                        Stream.of(expiryTimes),
                        Stream.of(clock.instant().plus(maximumExpirationTime))
                )
                .filter(Objects::nonNull)
                .min(Instant::compareTo)
                .orElseThrow();
    }
}
