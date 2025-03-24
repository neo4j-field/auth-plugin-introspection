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
package org.neo4j.auth.plugin.integration;

import static com.neo4j.harness.EnterpriseNeo4jBuilders.newInProcessBuilder;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertTrue;
import static org.mockserver.model.HttpRequest.request;

import com.neo4j.configuration.SecuritySettings;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

import org.junit.jupiter.api.*;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.matchers.Times;
import org.mockserver.model.HttpResponse;
import org.neo4j.configuration.GraphDatabaseSettings;
import org.neo4j.driver.*;
import org.neo4j.driver.Record;
import org.neo4j.driver.exceptions.AuthenticationException;
import org.neo4j.driver.exceptions.SecurityException;
import org.neo4j.harness.Neo4j;

public class IntrospectionAuthPluginIT {
    private static final Config config =
            Config.builder().withLogging(Logging.none()).withoutEncryption().build();
    public static final String BASE_INTROSPECTION_CONF = "base-introspection.conf";
    public static final String USERINFO_INTROSPECTION_CONF = "userinfo-introspection.conf";
    public static final String BOTH_INTROSPECTION_CONF = "both-introspection.conf";
    private Neo4j server;
    private Driver  driver;
    private ClientAndServer mockServer;
    private static Path tempFolder;

    private static final String token = "test-token";

    @BeforeAll
    public static void setup() throws IOException {
        tempFolder = Files.createTempDirectory("neo4j");
        tempFolder.toFile().deleteOnExit();
        tempFolder.resolve("conf").toFile().mkdirs();
        System.out.println("Temp folder: " + tempFolder.toAbsolutePath());
    }

    public void setUpNe4j(String confFile ) throws IOException {
        File configFile = new File(System.getProperty("user.dir") +
                "/src/test/resources/conf/"+confFile);
        Files.copy(configFile.toPath(), tempFolder.resolve("conf/introspection.conf"), StandardCopyOption.REPLACE_EXISTING);
        // Start up server with authentication enables
        server = newInProcessBuilder()
                .withConfig(GraphDatabaseSettings.neo4j_home,tempFolder.toAbsolutePath())
                .withConfig(GraphDatabaseSettings.auth_enabled, true)
                .withConfig(
                        SecuritySettings.authentication_providers,
                        List.of("plugin-org.neo4j.auth.plugin.IntrospectionAuthPlugin"))
                .withConfig(
                        SecuritySettings.authorization_providers,
                        List.of("plugin-org.neo4j.auth.plugin.IntrospectionAuthPlugin"))
                .build();
        driver = GraphDatabase.driver(server.boltURI(), AuthTokens.basic("neo4j", "neo4j"), config);
    }

    private void setUpMockServer(int postStatusCode, String postResponse) {
        setUpMockServer(postStatusCode,postResponse,500,null);
    }

    private void setUpMockServer(int postStatusCode, String postResponse, int getStatusCode, String getResponse) {
        mockServer = ClientAndServer.startClientAndServer(8080);
        mockServer.when(request().withMethod("POST"), Times.unlimited())
                .respond(HttpResponse.response().withStatusCode(postStatusCode)
                        .withBody(postResponse));
        mockServer.when(request().withMethod("GET"), Times.unlimited())
                .respond(HttpResponse.response().withStatusCode(getStatusCode)
                        .withBody(getResponse));
    }

    @AfterEach
    public void tearDown() {
        server.close();
        driver.close();
        if (mockServer != null) {
            mockServer.stop();
        }
    }

    @Test
    public void shouldAuthenticateNeo4jUser() throws IOException {
        setUpNe4j(BASE_INTROSPECTION_CONF);
        setUpMockServer(200, "{\"active\":true,\"username\":\"test\",\"groups\":[\"/Admin\"]}");
        //AuthTokens.bearer is not currently supported by the AuthPlugin.Adaptor
        try (Session session = driver.session(Session.class,AuthTokens.basic("test", token))) {
            Value single = session.run("RETURN 1").single().get(0);
            assertThat(single.asLong(), equalTo(1L));
        }
    }

    @Test
    public void shouldAuthenticateNeo4jUserUserInfo() throws IOException {
        setUpNe4j(USERINFO_INTROSPECTION_CONF);
        setUpMockServer(500, null,200,"{\"username\":\"test\",\"groups\":[\"/Admin\"]}");
        //AuthTokens.bearer is not currently supported by the AuthPlugin.Adaptor
        try (Session session = driver.session(Session.class,AuthTokens.basic("test", token))) {
            Value single = session.run("RETURN 1").single().get(0);
            assertThat(single.asLong(), equalTo(1L));
        }
    }

    @Test
    public void shouldAuthenticateNeo4jUserBoth() throws IOException {
        setUpNe4j(BOTH_INTROSPECTION_CONF);
        setUpMockServer(200, "{\"active\":true}",200,"{\"username\":\"test\",\"groups\":[\"/Admin\"]}");
        //AuthTokens.bearer is not currently supported by the AuthPlugin.Adaptor
        try (Session session = driver.session(Session.class,AuthTokens.basic("test", token))) {
            Value single = session.run("RETURN 1").single().get(0);
            assertThat(single.asLong(), equalTo(1L));
        }
    }

    @Test
    public void shouldFailAuthenticateUser() throws IOException {
        setUpNe4j(BASE_INTROSPECTION_CONF);
        setUpMockServer(200, "{\"active\":false}");
        try (Session session = driver.session(Session.class,AuthTokens.basic("dummy", token))) {
            Value single = session.run("RETURN 1").single().get(0);
            //should throw an exception
            assertThat(single.asLong(), equalTo(0L));
        } catch (AuthenticationException e) {
            assertTrue(true);
        }
    }

    @Test
    public void shouldFailIntrospection() throws IOException {
        setUpNe4j(BASE_INTROSPECTION_CONF);
        setUpMockServer(500, null);
        try (Session session = driver.session(Session.class,AuthTokens.basic("dummy", token))) {
            Value single = session.run("RETURN 1").single().get(0);
            //should throw an exception
            assertThat(single.asLong(), equalTo(0L));
        } catch (AuthenticationException e) {
            assertTrue(true);
        }
    }

    @Test
    public void shouldFailBadResponse() throws IOException {
        setUpNe4j(BASE_INTROSPECTION_CONF);
        setUpMockServer(200, "\"noJsonformat\":true");
        try (Session session = driver.session(Session.class,AuthTokens.basic("dummy", token))) {
            Value single = session.run("RETURN 1").single().get(0);
            //should throw an exception
            assertThat(single.asLong(), equalTo(0L));
        } catch (AuthenticationException e) {
            assertTrue(true);
        }
    }

    @Test
    public void shouldAuthenticateButFailToCreate() throws IOException {
        setUpNe4j(BASE_INTROSPECTION_CONF);
        setUpMockServer(200, "{\"active\":true,\"username\":\"moraeus\",\"groups\":[\"/Reader\"]}");
        try(Session session = driver.session(Session.class,AuthTokens.basic("moraeus", token))) {
            Value single = session.run("RETURN 1").single().get(0);
            assertThat(single.asLong(), equalTo(1L));

            session.run("CREATE (a:Person {name:'Kalle Moraeus', title:'Riksspelman'})");

            assertTrue(false);
        } catch (SecurityException e) {
            assertTrue(true);
        }
    }

    @Test
    public void shouldAuthenticateAndAuthorizeKalleMoraeusAsAdmin() throws IOException {
        setUpNe4j(BASE_INTROSPECTION_CONF);
        setUpMockServer(200, "{\"active\":true,\"username\":\"moraeus\",\"groups\":[\"/Admin\"]}");
        try(Session session = driver.session(Session.class,AuthTokens.basic("moraeus", token))) {

            session.run("CREATE (a:Person {name:'Kalle Moraeus', title:'Riksspelman'})");

            Result result =
                    session.run("MATCH (a:Person) WHERE a.name = 'Kalle Moraeus' RETURN a.name AS name, a.title AS title");
            assertTrue(result.hasNext());
            while (result.hasNext()) {
                Record record = result.next();
                assertThat(record.get("name").asString(), equalTo("Kalle Moraeus"));
                assertThat(record.get("title").asString(), equalTo("Riksspelman"));
                System.out.println(
                        record.get("title").asString() + " " + record.get("name").asString());
            }
        }
    }

    @Test
    public void shouldAuthenticateAndAuthorizeKalleMoraeusAsAdminUserInfo() throws IOException {
        setUpNe4j(USERINFO_INTROSPECTION_CONF);
        setUpMockServer(500, null,200,"{\"username\":\"test\",\"groups\":[\"/Admin\"]}");
        try(Session session = driver.session(Session.class,AuthTokens.basic("moraeus", token))) {

            session.run("CREATE (a:Person {name:'Kalle Moraeus', title:'Riksspelman'})");

            Result result =
                    session.run("MATCH (a:Person) WHERE a.name = 'Kalle Moraeus' RETURN a.name AS name, a.title AS title");
            assertTrue(result.hasNext());
            while (result.hasNext()) {
                Record record = result.next();
                assertThat(record.get("name").asString(), equalTo("Kalle Moraeus"));
                assertThat(record.get("title").asString(), equalTo("Riksspelman"));
                System.out.println(
                        record.get("title").asString() + " " + record.get("name").asString());
            }
        }
    }

    @Test
    public void shouldFailBadConfig() throws IOException {
        setUpNe4j(BASE_INTROSPECTION_CONF);
        setUpMockServer(404, null);
        try (Session session = driver.session(Session.class,AuthTokens.basic("dummy", token))) {
            Value single = session.run("RETURN 1").single().get(0);
            //should throw an exception
            assertThat(single.asLong(), equalTo(0L));
        } catch (AuthenticationException e) {
            assertTrue(true);
        }
    }

}
