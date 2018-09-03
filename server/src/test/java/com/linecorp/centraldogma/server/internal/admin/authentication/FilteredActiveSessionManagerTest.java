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
package com.linecorp.centraldogma.server.internal.admin.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.CompletableFuture;

import org.junit.Test;

import com.linecorp.centraldogma.server.authentication.AuthenticatedSession;

public class FilteredActiveSessionManagerTest {

    @Test
    public void shouldReturnNonNull() {
        final AuthenticatedSession expiredAfterOneHour = createSession(Instant.now().plus(1, ChronoUnit.HOURS));
        final SessionManager delegate = mock(SessionManager.class);
        when(delegate.get(any())).thenReturn(CompletableFuture.completedFuture(expiredAfterOneHour));

        final FilteredActiveSessionManager manager = new FilteredActiveSessionManager(delegate);
        assertThat(manager.get("id").join()).isNotNull()
                                            .isEqualTo(expiredAfterOneHour);
    }

    @Test
    public void shouldReturnNull() {
        final AuthenticatedSession expiredSession = createSession(Instant.EPOCH);
        final SessionManager delegate = mock(SessionManager.class);
        when(delegate.get(any())).thenReturn(CompletableFuture.completedFuture(expiredSession));

        final FilteredActiveSessionManager manager = new FilteredActiveSessionManager(delegate);
        assertThat(manager.get("id").join()).isNull();
    }

    private static AuthenticatedSession createSession(Instant expirationTime) {
        return new AuthenticatedSession("id", "username", Instant.EPOCH, expirationTime, null);
    }
}
