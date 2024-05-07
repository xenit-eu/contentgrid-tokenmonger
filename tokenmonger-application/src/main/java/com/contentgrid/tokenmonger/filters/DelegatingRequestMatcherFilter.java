package com.contentgrid.tokenmonger.filters;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Delegate;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.core.env.EnvironmentCapable;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.context.ServletContextAware;
import org.springframework.web.context.support.StandardServletEnvironment;

/**
 * Filter that only delegates to a different filter if the request matcher matches
 */
@RequiredArgsConstructor
public class DelegatingRequestMatcherFilter implements Filter, BeanNameAware, EnvironmentAware, EnvironmentCapable,
        ServletContextAware, InitializingBean, DisposableBean {
    private final RequestMatcher matcher;

    private Environment environment;

    @Delegate
    private final Filter delegate;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if(request instanceof HttpServletRequest httpServletRequest && matcher.matches(httpServletRequest)) {
            delegate.doFilter(request, response, chain);
        } else {
            chain.doFilter(request, response);
        }
    }

    @Override
    public void setBeanName(String name) {
        if(delegate instanceof BeanNameAware beanNameAware)  {
            beanNameAware.setBeanName(name);
        }
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if(delegate instanceof InitializingBean initializingBean) {
            initializingBean.afterPropertiesSet();
        }
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
        if(delegate instanceof EnvironmentAware environmentAware) {
            environmentAware.setEnvironment(environment);
        }
    }

    @Override
    public Environment getEnvironment() {
        if(delegate instanceof EnvironmentCapable environmentCapable) {
            return environmentCapable.getEnvironment();
        }
        if(this.environment == null) {
            setEnvironment(new StandardServletEnvironment());
        }
        return this.environment;
    }

    @Override
    public void setServletContext(ServletContext servletContext) {
        if(delegate instanceof ServletContextAware servletContextAware) {
            servletContextAware.setServletContext(servletContext);
        }
    }
}
