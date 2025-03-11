# neo4j-auth-plugin-introspection
Introspection authentication and authorization plugins for Neo4j

This plugin is base on examples from https://github.com/neo4j/neo4j-example-auth-plugins/tree/dev/plugins

You have to run this with Java 17.

The Maven Repo https://m2.neo4j.com/enterprise requires credentials.  Contact support for this.

If you just want to build the plugins, you can choose to ignore integration tests by running:

    mvn clean install -DskipITs 

## Install plugins in Neo4j
Copy the output jar file into the plugins folder of Neo4j Enterprise Edition 5.0 or later:

    cp plugins/target/neo4j-auth-plugin-introspection-<VERSION>.jar <NEO4J-HOME>/plugins/

Copy the introspection.conf configuration file into the config folder of Neo4j Enterprise Edition 5.0 or later:

    cp plugins/main/resources/introspection.conf <NEO4J-HOME>/config/
If no file is found in the the config folder, the resource file will be used.

Edit the Introspection configuration file you just copied to `<NEO4J-HOME>/config/` and update the setting for your oauth provider

Edit the Neo4j configuration file `<NEO4J-HOME>/conf/neo4j.conf` and add the `dbms.security.authentication_providers` 
and `dbms.security.authorization_providers` settings, e.g.:

    dbms.security.authentication_providers=plugin-org.neo4j.auth.plugin.IntrospectionAuthPlugin
    dbms.security.authorization_providers=plugin-org.neo4j.auth.plugin.IntrospectionAuthPlugin

You can also enable multiple plugins simultaneously e.g.:

    dbms.security.authentication_providers=plugin-MyAuthPlugin1,plugin-MyAuthPlugin2

You can also toggle authentication and authorization enabled individually by only adding it to either of the settings: 

    dbms.security.authentication_providers=plugin-MyAuthPlugin1
    dbms.security.authorization_providers=plugin-MyAuthPlugin2

(NOTE: Any plugin implementing the simplified `AuthPlugin` interface must be in both `dbms.security.authentication_providers`
 and `dbms.security.authorization_providers`, or it will not be loaded)

To enable SSO using the Neo4j Browser follow the instructions here: https://neo4j.com/docs/operations-manual/current/tutorial/tutorial-sso-configuration/
