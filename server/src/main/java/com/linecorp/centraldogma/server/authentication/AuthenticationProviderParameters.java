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
package com.linecorp.centraldogma.server.authentication;

import static java.util.Objects.requireNonNull;

import java.io.File;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;
import java.util.function.Supplier;

import javax.annotation.Nullable;

import com.linecorp.armeria.common.HttpRequest;
import com.linecorp.armeria.server.auth.Authorizer;
import com.linecorp.centraldogma.server.CentralDogmaConfig;

/**
 * Parameters which are used to create a new {@link AuthenticationProvider} instance.
 */
public final class AuthenticationProviderParameters {

    private final Authorizer<HttpRequest> authorizer;
    private final CentralDogmaConfig config;
    @Nullable
    private final File securityConfigFile;
    private final Supplier<String> sessionIdGenerator;
    private final Function<AuthenticatedSession, CompletableFuture<Void>> loginSessionPropagator;
    private final Function<String, CompletableFuture<Void>> logoutSessionPropagator;

    /**
     * Creates a new {@link AuthenticationProvider} instance.
     *
     * @param authorizer the {@link Authorizer} which is used to authenticate a session token
     * @param config the configuration for the Central Dogma server
     * @param securityConfigFile the {@link File} which is specified by the {@code -securityConfig} parameter
     *                           when starting the Central Dogma server
     * @param sessionIdGenerator the session ID generator which must be used when generating a new session ID
     * @param loginSessionPropagator the function which propagates the {@link AuthenticatedSession}
     *                               to the other replicas
     * @param logoutSessionPropagator a function which propagates the logged out session ID to the other
     *                                replicas
     */
    public AuthenticationProviderParameters(
            Authorizer<HttpRequest> authorizer,
            CentralDogmaConfig config,
            @Nullable File securityConfigFile,
            Supplier<String> sessionIdGenerator,
            Function<AuthenticatedSession, CompletableFuture<Void>> loginSessionPropagator,
            Function<String, CompletableFuture<Void>> logoutSessionPropagator) {
        this.authorizer = requireNonNull(authorizer, "authorizer");
        this.config = requireNonNull(config, "config");
        this.securityConfigFile = securityConfigFile;
        this.sessionIdGenerator = requireNonNull(sessionIdGenerator, "sessionIdGenerator");
        this.loginSessionPropagator = requireNonNull(loginSessionPropagator, "loginSessionPropagator");
        this.logoutSessionPropagator = requireNonNull(logoutSessionPropagator, "logoutSessionPropagator");
    }

    /**
     * Returns an {@link Authorizer} which is used to authenticate a session token.
     */
    public Authorizer<HttpRequest> authorizer() {
        return authorizer;
    }

    /**
     * Returns the configuration for the Central Dogma server.
     */
    public CentralDogmaConfig config() {
        return config;
    }

    /**
     * Returns a {@link File} which is specified by the {@code -securityConfig} parameter when starting
     * the Central Dogma server.
     */
    @Nullable
    public File securityConfigFile() {
        return securityConfigFile;
    }

    /**
     * Returns the session ID generator which must be used when generating a new session ID. The default
     * session manager relies on the session ID format, so if the {@link AuthenticationProvider} does not
     * use this generator the session might be rejected from the session manager.
     */
    public Supplier<String> sessionIdGenerator() {
        return sessionIdGenerator;
    }

    /**
     * Returns a function which propagates the {@link AuthenticatedSession} to the other replicas.
     * It would be invoked after a login process is successfully completed.
     */
    public Function<AuthenticatedSession, CompletableFuture<Void>> loginSessionPropagator() {
        return loginSessionPropagator;
    }

    /**
     * Returns a function which propagates the logged out session ID to the other replicas.
     * It would be invoked after a logout process is successfully completed.
     */
    public Function<String, CompletableFuture<Void>> logoutSessionPropagator() {
        return logoutSessionPropagator;
    }
}
