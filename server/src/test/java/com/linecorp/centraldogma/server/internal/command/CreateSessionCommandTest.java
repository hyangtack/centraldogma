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

package com.linecorp.centraldogma.server.internal.command;

import static com.linecorp.centraldogma.testing.internal.TestUtil.assertJsonConversion;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.Test;

import com.linecorp.centraldogma.common.Author;
import com.linecorp.centraldogma.server.authentication.AuthenticatedSession;

public class CreateSessionCommandTest {

    @Test
    public void testJsonConversion() throws Exception {
        final AuthenticatedSession session =
                new AuthenticatedSession("session-id-12345",
                                         "foo",
                                         Instant.EPOCH,
                                         Instant.EPOCH.plus(1, ChronoUnit.MINUTES),
                                         "serializable_raw_session_object");

        final String encodedSession =
                "rO0ABXNyAERjb20ubGluZWNvcnAuY2VudHJhbGRvZ21hLnNlcnZlci5hdXRoZW50aWNhdGlvbi5BdXRo" +
                "ZW50aWNhdGVkU2Vzc2lvbjsGPBR+rwSBAgAFTAAMY3JlYXRpb25UaW1ldAATTGphdmEvdGltZS9JbnN0" +
                "YW50O0wADmV4cGlyYXRpb25UaW1lcQB+AAFMAAJpZHQAEkxqYXZhL2xhbmcvU3RyaW5nO0wACnJhd1Nl" +
                "c3Npb250ABZMamF2YS9pby9TZXJpYWxpemFibGU7TAAIdXNlcm5hbWVxAH4AAnhwc3IADWphdmEudGlt" +
                "ZS5TZXKVXYS6GyJIsgwAAHhwdw0CAAAAAAAAAAAAAAAAeHNxAH4ABXcNAgAAAAAAAAA8AAAAAHh0ABBz" +
                "ZXNzaW9uLWlkLTEyMzQ1dAAfc2VyaWFsaXphYmxlX3Jhd19zZXNzaW9uX29iamVjdHQAA2Zvbw==";

        assertJsonConversion(
                new CreateSessionCommand(1234L, new Author("foo", "bar@baz.com"), session),
                Command.class,
                '{' +
                "  \"type\": \"CREATE_SESSIONS\"," +
                "  \"timestamp\": 1234," +
                "  \"author\": {" +
                "    \"name\": \"foo\"," +
                "    \"email\": \"bar@baz.com\"" +
                "  }," +
                "  \"session\": \"" + encodedSession + '"' +
                '}');
    }
}
