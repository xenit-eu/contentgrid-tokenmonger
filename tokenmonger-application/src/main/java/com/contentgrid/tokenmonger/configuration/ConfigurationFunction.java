package com.contentgrid.tokenmonger.configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.Synchronized;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@RequiredArgsConstructor
class ConfigurationFunction<T> implements Function<HttpSecurity, List<T>> {

    private final UnaryOperator<T> postProcessor;
    private final List<BiConsumer<List<T>, HttpSecurity>> configurers = new ArrayList<>();

    public void add(@NonNull BiConsumer<List<T>, HttpSecurity> configurer) {
        this.configurers.add(configurer);
    }

    public void add(@NonNull Consumer<List<T>> configurer) {
        add((list, httpSecurity) -> configurer.accept(list));
    }

    public void supply(@NonNull Function<HttpSecurity, ? extends T> supplier) {
        add((list, httpSecurity) -> Optional.ofNullable(supplier.apply(httpSecurity)).ifPresent(list::add));
    }

    public void item(@NonNull T item) {
        add((list, httpSecurity) -> list.add(item));
    }


    @Override
    public List<T> apply(HttpSecurity httpSecurity) {
        var list = new ArrayList<T>();
        for (BiConsumer<List<T>, HttpSecurity> configurer : configurers) {
            configurer.accept(list, httpSecurity);
        }

        return list.stream()
                .map(this.postProcessor)
                .toList();
    }
}
