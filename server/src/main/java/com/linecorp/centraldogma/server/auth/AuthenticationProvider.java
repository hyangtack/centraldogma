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
package com.linecorp.centraldogma.server.auth;

import static com.linecorp.centraldogma.internal.api.v1.HttpApiV1Constants.API_V0_PATH_PREFIX;
import static com.linecorp.centraldogma.internal.api.v1.HttpApiV1Constants.API_V1_PATH_PREFIX;

import java.util.Set;
import java.util.function.Function;

import com.google.common.base.Ascii;
import com.google.common.collect.ImmutableSet;

import com.linecorp.armeria.common.HttpRequest;
import com.linecorp.armeria.common.HttpResponse;
import com.linecorp.armeria.server.PathMapping;
import com.linecorp.armeria.server.Service;
import com.linecorp.armeria.server.ServiceWithPathMappings;
import com.linecorp.centraldogma.server.CentralDogmaConfig;

/**
 * An interface which configures the authentication layer for the Central Dogma server.
 */
public interface AuthenticationProvider {

    /**
     * Returns the set of {@link PathMapping}s which handles a login request. It is necessary only if
     * an authentication protocol requires a login feature provided by the server.
     */
    static Set<PathMapping> loginServicePathMappings() {
        return ImmutableSet.of(PathMapping.ofExact(API_V0_PATH_PREFIX + "authenticate"),
                               PathMapping.ofExact(API_V1_PATH_PREFIX + "login"));
    }

    /**
     * Returns the set of {@link PathMapping}s which handles a logout request. It is necessary only if
     * an authentication protocol requires a logout feature provided by the server.
     */
    static Set<PathMapping> logoutServicePathMappings() {
        return ImmutableSet.of(PathMapping.ofExact(API_V0_PATH_PREFIX + "logout"),
                               PathMapping.ofExact(API_V1_PATH_PREFIX + "logout"));
    }

    /**
     * Returns a {@link Function} which normalizes a login name based on the
     * {@link CentralDogmaConfig#caseSensitiveLoginNames()} property.
     */
    static Function<String, String> loginNameNormalizer(CentralDogmaConfig cfg) {
        return cfg.caseSensitiveLoginNames() ? Function.identity() : Ascii::toLowerCase;
    }

    /**
     * Creates a decorator which initiates the authentication if a request is not authenticated.
     */
    Function<Service<HttpRequest, HttpResponse>,
            Service<HttpRequest, HttpResponse>> newAuthenticationDecorator();

    /**
     * Creates a {@link Service} which handles messages for the authentication.
     */
    Iterable<ServiceWithPathMappings<HttpRequest, HttpResponse>> newAuthenticationServices();
}
