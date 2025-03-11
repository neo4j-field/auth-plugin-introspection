/**
 * Copyright (c) 2002-2017 "Neo Technology,"
 * Network Engine for Objects in Lund AB [http://neotechnology.com]
 *
 * This file is part of Neo4j.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.neo4j.auth.plugin;

import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.neo4j.server.security.enterprise.auth.plugin.api.AuthProviderOperations;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;

public class IntrospectionAuthPluginTest {
    @Test
    public void shouldLogErrorOnNonExistingConfigFile() {
        // Given
        IntrospectionAuthPlugin plugin = new IntrospectionAuthPlugin();
        AuthProviderOperations api = mock(AuthProviderOperations.class);
        AuthProviderOperations.Log log = mock(AuthProviderOperations.Log.class);

        when(api.neo4jHome()).thenReturn(Paths.get(""));
        when(api.log()).thenReturn(log);

        // When
        plugin.initialize(api);

        // Then
        verify(log).info(startsWith("org.neo4j.auth.plugin.IntrospectionAuthPlugin"));
    }
}
