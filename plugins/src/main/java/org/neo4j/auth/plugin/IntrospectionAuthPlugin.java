/**
 * Copyright (c) 2002-2017 "Neo Technology,"
 * Network Engine for Objects in Lund AB [http://neotechnology.com]
 * <p>
 * This file is part of Neo4j.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 *     http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.neo4j.auth.plugin;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthProviderOperations;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthToken;
import com.neo4j.server.security.enterprise.auth.plugin.api.AuthenticationException;
import com.neo4j.server.security.enterprise.auth.plugin.spi.AuthInfo;
import com.neo4j.server.security.enterprise.auth.plugin.spi.AuthPlugin;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class IntrospectionAuthPlugin extends AuthPlugin.Adapter {
    private AuthProviderOperations api;
    private String clientId;
    private String clientSecret;
    private String introspectionUri;
    private String userNameField;
    private String groupField;
    private Map<String,String> groupMap;

    @Override
    public AuthInfo authenticateAndAuthorize(AuthToken authToken) throws AuthenticationException {
        char[] password = authToken.credentials();
        String access_token = new String (password);
        Set<String> neo4JRoles = new HashSet<>();

        try
        {
            Map<String,Object> results = getIntrospectionResults(introspectionUri,access_token);

            if(results==null||!(boolean)results.getOrDefault("active",false)){
                throw new AuthenticationException("Introspection failed");
            }

            String user = (String)results.get(userNameField);
            api.log().info("Log in by " + user);

            List<String> groups = (List<String>) results.get(groupField);
            for(String group : groups){
                if(groupMap.containsKey(group)){
                    neo4JRoles.add(groupMap.get(group));
                }
            }

            api.log().debug("Neo4j Roles for "+user+" are : "+neo4JRoles);
            return(AuthInfo.of(user, neo4JRoles));
        } catch (AuthenticationException e) {
            api.log().error("Invalid JWT! " + e);
            throw e;
        } catch (Exception e) {
            api.log().error("Exception!  " + e);
            throw new AuthenticationException(e.getMessage());
        }
    }

    @Override
    public void initialize(AuthProviderOperations authProviderOperations) {
        api = authProviderOperations;
        api.log().info( this.name() + " initialized!" );

        loadConfig();
    }

    private void loadConfig() {
        Properties properties = loadProperties();

        introspectionUri = properties.getProperty( "auth.oauth.introspection_uri" );
        clientSecret = properties.getProperty( "auth.oauth.client_secret" );
        clientId = properties.getProperty( "auth.oauth.client_id" );
        userNameField = properties.getProperty( "auth.oauth.claims.username","username" );
        groupField = properties.getProperty( "auth.oauth.claims.groups","groups" );
        String groups = properties.getProperty( "auth.oauth.group_to_role_mapping" );
        groupMap = new HashMap<>();
        if(groups!=null){
            for(String group: groups.split(";")){
                String[] map = group.split("=");
                try{
                    groupMap.put(map[0].replace("\"","").trim(),map[1].trim());
                } catch (Exception e){
                    api.log().error("Error parsing group mapping: " + group);
                }
            }
        } else {
            api.log().error("No groups found in config file!");
        }


    }

    private Properties loadProperties() {
        Properties properties = new Properties();
        Path configFile = api.neo4jHome().resolve( "conf/introspection.conf");

        try {
            InputStream inputStream;
            if(Files.exists(configFile)){
                inputStream = new FileInputStream(configFile.toFile());
            } else {
                api.log().warn("conf/introspection.conf not found.  Loading configuration from the JAR resource");
                inputStream = IntrospectionAuthPlugin.class.getResourceAsStream("/introspection.conf");
            }
            properties.load(inputStream);
        } catch (IOException e) {
            api.log().error("Failed to load config file '" + configFile + "'.");
        }
        return properties;
    }


    private Map<String, Object> getIntrospectionResults(String requestUrl, String access_token) throws Exception {
        Map<String,String> parameters = new HashMap<>();
        parameters.put("token", access_token);
        parameters.put("client_id", clientId);
        parameters.put("client_secret", clientSecret);

        URL url = new URL(requestUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setDoOutput(true);

        StringBuilder postData = new StringBuilder();
        for (Map.Entry<String, String> param : parameters.entrySet()) {
            if (!postData.isEmpty()) postData.append('&');
            postData.append(param.getKey()).append('=').append(param.getValue());
        }

        byte[] postDataBytes = postData.toString().getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = connection.getOutputStream()) {
            os.write(postDataBytes);
            os.flush();
        }

        int responseCode = connection.getResponseCode();
        api.log().debug("Response Code: " + responseCode);

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuilder response = new StringBuilder();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        api.log().debug("Response Body: " + response);

        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(response.toString(), HashMap.class);
    }
}
