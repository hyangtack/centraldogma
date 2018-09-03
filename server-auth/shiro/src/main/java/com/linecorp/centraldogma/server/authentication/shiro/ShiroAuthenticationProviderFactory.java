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
package com.linecorp.centraldogma.server.authentication.shiro;

import static java.util.Objects.requireNonNull;

import org.apache.shiro.config.Ini;

import com.linecorp.centraldogma.server.authentication.AuthenticationProvider;
import com.linecorp.centraldogma.server.authentication.AuthenticationProviderFactory;
import com.linecorp.centraldogma.server.authentication.AuthenticationProviderParameters;

/**
 * A factory for creating an Apache Shiro based {@link AuthenticationProvider}.
 */
public final class ShiroAuthenticationProviderFactory implements AuthenticationProviderFactory {
    @Override
    public AuthenticationProvider create(AuthenticationProviderParameters parameters) {
        requireNonNull(parameters, "parameters");
        final Ini iniConfig = Ini.fromResourcePath(
                requireNonNull(parameters.securityConfigFile(), "securityConfigFile").getPath());
        return new ShiroAuthenticationProvider(parameters.config(),
                                               iniConfig,
                                               parameters.authorizer(),
                                               parameters.sessionIdGenerator(),
                                               parameters.loginSessionPropagator(),
                                               parameters.logoutSessionPropagator());
    }
}
