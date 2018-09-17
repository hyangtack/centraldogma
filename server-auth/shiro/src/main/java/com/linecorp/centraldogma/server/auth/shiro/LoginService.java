/*
 * Copyright 2017 LINE Corporation
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

import static com.linecorp.centraldogma.server.internal.api.HttpApiUtil.throwResponse;
import static java.util.Objects.requireNonNull;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.function.Function;

import javax.annotation.Nullable;

import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.Subject.Builder;
import org.apache.shiro.util.ThreadContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.benmanes.caffeine.cache.Cache;

import com.linecorp.armeria.common.AggregatedHttpMessage;
import com.linecorp.armeria.common.HttpRequest;
import com.linecorp.armeria.common.HttpResponse;
import com.linecorp.armeria.common.HttpStatus;
import com.linecorp.armeria.common.MediaType;
import com.linecorp.armeria.common.util.Exceptions;
import com.linecorp.armeria.server.AbstractHttpService;
import com.linecorp.armeria.server.PathMapping;
import com.linecorp.armeria.server.ServiceRequestContext;
import com.linecorp.armeria.server.ServiceWithPathMappings;
import com.linecorp.armeria.server.auth.AuthTokenExtractors;
import com.linecorp.armeria.server.auth.BasicToken;
import com.linecorp.centraldogma.internal.Jackson;
import com.linecorp.centraldogma.internal.api.v1.AccessToken;
import com.linecorp.centraldogma.server.auth.AuthenticatedSession;
import com.linecorp.centraldogma.server.auth.AuthenticationProvider;
import com.linecorp.centraldogma.server.internal.api.HttpApiUtil;

import io.netty.handler.codec.http.QueryStringDecoder;

/**
 * A service to handle a login request to Central Dogma Web admin service.
 */
final class LoginService extends AbstractHttpService
        implements ServiceWithPathMappings<HttpRequest, HttpResponse> {
    private static final Logger logger = LoggerFactory.getLogger(LoginService.class);

    private static final Duration ONE_MINUTE = Duration.ofMinutes(1);

    private final SecurityManager securityManager;
    private final Function<String, String> loginNameNormalizer;
    private final Cache<String, AccessToken> cache;
    private final Function<AuthenticatedSession, CompletableFuture<Void>> loginSessionPropagator;
    private final Duration sessionValidDuration;
    private final Duration accessTokenTouchableDuration;

    LoginService(SecurityManager securityManager,
                 Function<String, String> loginNameNormalizer,
                 Cache<String, AccessToken> cache,
                 Function<AuthenticatedSession, CompletableFuture<Void>> loginSessionPropagator,
                 Duration sessionValidDuration) {
        this.securityManager = requireNonNull(securityManager, "securityManager");
        this.loginNameNormalizer = requireNonNull(loginNameNormalizer, "loginNameNormalizer");
        this.cache = requireNonNull(cache, "cache");
        this.loginSessionPropagator = requireNonNull(loginSessionPropagator, "loginSessionPropagator");
        this.sessionValidDuration = requireNonNull(sessionValidDuration, "sessionValidDuration");
        accessTokenTouchableDuration =
                sessionValidDuration.compareTo(ONE_MINUTE) < 0 ? sessionValidDuration : ONE_MINUTE;
    }

    @Override
    public Set<PathMapping> pathMappings() {
        return AuthenticationProvider.loginServicePathMappings();
    }

    @Override
    protected HttpResponse doPost(ServiceRequestContext ctx, HttpRequest req) throws Exception {
        return HttpResponse.from(
                req.aggregate().thenApply(this::usernamePassword)
                   .thenApplyAsync(usernamePassword -> {
                       ThreadContext.bind(securityManager);
                       Subject currentUser = null;
                       try {
                           // If an access token for the user exists in the cache, it will be returned with
                           // recalculated expires_in seconds.
                           final AccessToken currentUserToken = currentUserTokenIfPresent(usernamePassword);
                           if (currentUserToken != null) {
                               return HttpResponse.of(HttpStatus.OK, MediaType.JSON_UTF_8,
                                                      Jackson.writeValueAsBytes(currentUserToken));
                           }

                           currentUser = new Builder(securityManager).buildSubject();
                           currentUser.login(usernamePassword);

                           final Session session = currentUser.getSession(false);
                           final String sessionId = session.getId().toString();
                           return HttpResponse.from(
                                   processLogin(ctx, usernamePassword, currentUser, sessionId));
                       } catch (IncorrectCredentialsException e) {
                           // Not authorized
                           logger.debug("{} Incorrect login: {}", ctx, usernamePassword.getUsername());
                           return HttpApiUtil.newResponse(HttpStatus.UNAUTHORIZED, "Incorrect login");
                       } catch (Throwable t) {
                           logger.warn("{} Failed to authenticate: {}", ctx, usernamePassword.getUsername(), t);
                           return HttpApiUtil.newResponse(HttpStatus.INTERNAL_SERVER_ERROR, t);
                       } finally {
                           logoutUserQuietly(ctx, currentUser);
                           ThreadContext.unbindSecurityManager();
                       }
                   }, ctx.blockingTaskExecutor()));
    }

    private CompletionStage<HttpResponse> processLogin(
            ServiceRequestContext ctx, UsernamePasswordToken usernamePassword,
            Subject currentUser, String sessionId) {
        final AuthenticatedSession session =
                AuthenticatedSession.of(sessionId, usernamePassword.getUsername(), sessionValidDuration);

        // loginSessionPropagator will propagate the authenticated session to all replicas in the cluster.
        return loginSessionPropagator.apply(session).handle((unused, cause) -> {
            if (cause != null) {
                ThreadContext.bind(securityManager);
                logoutUserQuietly(ctx, currentUser);
                ThreadContext.unbindSecurityManager();
                return HttpApiUtil.newResponse(HttpStatus.INTERNAL_SERVER_ERROR, Exceptions.peel(cause));
            }

            logger.debug("{} Logged in: {} ({})", ctx, usernamePassword.getUsername(), sessionId);

            // expires_in means valid seconds of the token from the creation.
            final AccessToken accessToken = new AccessToken(sessionId, sessionValidDuration.getSeconds());

            try {
                final byte[] body = Jackson.writeValueAsBytes(accessToken);
                // Put the access token in order to ensure that returning the same access token for
                // the same user within a certain time period.
                cache.put(usernamePassword.getUsername(), accessToken);
                return HttpResponse.of(HttpStatus.OK, MediaType.JSON_UTF_8, body);
            } catch (JsonProcessingException e) {
                return HttpApiUtil.newResponse(HttpStatus.INTERNAL_SERVER_ERROR, e);
            }
        });
    }

    private static void logoutUserQuietly(ServiceRequestContext ctx, @Nullable Subject user) {
        try {
            if (user != null && !user.isAuthenticated()) {
                user.logout();
            }
        } catch (Exception cause) {
            logger.debug("{} Failed to logout a user: {}", ctx, user, cause);
        }
    }

    /**
     * Returns {@link UsernamePasswordToken} which holds a username and a password.
     */
    private UsernamePasswordToken usernamePassword(AggregatedHttpMessage req) {
        // check the Basic HTTP authentication first (https://tools.ietf.org/html/rfc7617)
        final BasicToken basicToken = AuthTokenExtractors.BASIC.apply(req.headers());
        if (basicToken != null) {
            return new UsernamePasswordToken(basicToken.username(), basicToken.password());
        }

        final MediaType mediaType = req.headers().contentType();
        if (mediaType != MediaType.FORM_DATA) {
            return throwResponse(HttpStatus.BAD_REQUEST,
                                 "The content type of a login request must be '%s'.", MediaType.FORM_DATA);
        }

        final Map<String, List<String>> parameters = new QueryStringDecoder(
                req.content().toStringUtf8(), false).parameters();

        // assume that the grant_type is "password"
        final List<String> usernames = parameters.get("username");
        final List<String> passwords = parameters.get("password");
        if (usernames != null && passwords != null) {
            final String username = usernames.get(0);
            final String password = passwords.get(0);
            return new UsernamePasswordToken(loginNameNormalizer.apply(username), password);
        }

        return throwResponse(HttpStatus.BAD_REQUEST, "A login request must contain username and password.");
    }

    @Nullable
    private AccessToken currentUserTokenIfPresent(UsernamePasswordToken usernamePassword) {
        securityManager.authenticate(usernamePassword);

        // Because securityManager.authenticate does not throw any Exception, the user is authenticated.
        final AccessToken token = cache.getIfPresent(usernamePassword.getUsername());
        if (token != null) {
            final Instant now = Instant.now();
            final Duration gap = Duration.between(now.plus(accessTokenTouchableDuration), token.deadline());
            if (!gap.isNegative()) {
                return new AccessToken(token.accessToken(),
                                       Duration.between(now, token.deadline()).getSeconds());
            }
        }
        return null;
    }
}
