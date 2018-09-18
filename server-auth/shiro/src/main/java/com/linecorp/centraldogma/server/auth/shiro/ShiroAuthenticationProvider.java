/*
 * Copyright 2018 LINE Corporation
 *
 * LINE Corporation licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package com.linecorp.centraldogma.server.auth.shiro;

import static java.util.Objects.requireNonNull;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.function.Supplier;

import org.apache.shiro.config.Ini;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.mgt.DefaultSecurityManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.util.Factory;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.collect.ImmutableList;

import com.linecorp.armeria.common.HttpRequest;
import com.linecorp.armeria.common.HttpResponse;
import com.linecorp.armeria.server.Service;
import com.linecorp.armeria.server.ServiceWithPathMappings;
import com.linecorp.armeria.server.auth.Authorizer;
import com.linecorp.armeria.server.auth.HttpAuthServiceBuilder;
import com.linecorp.centraldogma.internal.api.v1.AccessToken;
import com.linecorp.centraldogma.server.auth.AuthenticatedSession;
import com.linecorp.centraldogma.server.auth.AuthenticationConfig;
import com.linecorp.centraldogma.server.auth.AuthenticationProvider;

/**
 * Apache Shiro based {@link AuthenticationProvider} implementation.
 */
public final class ShiroAuthenticationProvider implements AuthenticationProvider {

    private final AuthenticationConfig authConfig;
    private final Ini config;
    private final Authorizer<HttpRequest> authorizer;
    private final Supplier<String> sessionIdGenerator;
    private final Function<AuthenticatedSession, CompletableFuture<Void>> loginSessionPropagator;
    private final Function<String, CompletableFuture<Void>> logoutSessionPropagator;

    ShiroAuthenticationProvider(AuthenticationConfig authConfig,
                                Ini config,
                                Authorizer<HttpRequest> authorizer,
                                Supplier<String> sessionIdGenerator,
                                Function<AuthenticatedSession, CompletableFuture<Void>> loginSessionPropagator,
                                Function<String, CompletableFuture<Void>> logoutSessionPropagator) {
        this.authConfig = requireNonNull(authConfig, "authConfig");
        this.config = requireNonNull(config, "config");
        this.authorizer = requireNonNull(authorizer, "authorizer");
        this.sessionIdGenerator = requireNonNull(sessionIdGenerator, "sessionIdGenerator");
        this.loginSessionPropagator = requireNonNull(loginSessionPropagator, "loginSessionPropagator");
        this.logoutSessionPropagator = requireNonNull(logoutSessionPropagator, "logoutSessionPropagator");
    }

    @Override
    public Function<Service<HttpRequest, HttpResponse>,
            Service<HttpRequest, HttpResponse>> newAuthenticationDecorator() {
        return delegate -> new HttpAuthServiceBuilder().add(authorizer).build(delegate);
    }

    @Override
    public Iterable<ServiceWithPathMappings<HttpRequest, HttpResponse>> newAuthenticationServices() {
        final Factory<SecurityManager> factory = new IniSecurityManagerFactory(config) {
            @Override
            protected SecurityManager createDefaultInstance() {
                final DefaultSessionManager sessionManager = new DefaultSessionManager();
                // This session DAO is required to cache the session in a very short time, especially while
                // logging in to the Central Dogma server. After that, the general session manager provided
                // by Central Dogma server will be working for the session management.
                sessionManager.setSessionDAO(new LimitedMemorySessionDAO(sessionIdGenerator,
                                                                         64, Duration.ofHours(1)));

                final DefaultSecurityManager securityManager = new DefaultSecurityManager();
                securityManager.setSessionManager(sessionManager);

                return securityManager;
            }
        };

        final SecurityManager securityManager = factory.getInstance();
        final Cache<String, AccessToken> sessionCache = Caffeine.from(authConfig.sessionCacheSpec()).build();
        final Duration sessionValidDuration = Duration.ofMillis(authConfig.sessionTimeoutMillis());

        return ImmutableList.of(new LoginService(securityManager, authConfig.loginNameNormalizer(),
                                                 sessionCache, loginSessionPropagator, sessionValidDuration),
                                new LogoutService(securityManager, sessionCache, logoutSessionPropagator));
    }
}
