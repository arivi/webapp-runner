/**
 * Copyright (c) 2012, John Simone
 * All rights reserved.
 * <p/>
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided
 * that the following conditions are met:
 * <p/>
 * Redistributions of source code must retain the above copyright notice, this list of conditions and the
 * following disclaimer.
 * <p/>
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and
 * the following disclaimer in the documentation and/or other materials provided with the distribution.
 * <p/>
 * Neither the name of John Simone nor the names of its contributors may be used to endorse or
 * promote products derived from this software without specific prior written permission.
 * <p/>
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package webapp.runner.launch;

import com.beust.jcommander.JCommander;
import org.apache.catalina.Context;
import org.apache.catalina.Globals;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleListener;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Role;
import org.apache.catalina.Server;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.core.StandardServer;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.deploy.SecurityCollection;
import org.apache.catalina.deploy.SecurityConstraint;
import org.apache.catalina.startup.ExpandWar;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.users.MemoryUserDatabase;
import org.apache.catalina.users.MemoryUserDatabaseFactory;

import javax.naming.CompositeName;
import javax.naming.StringRefAddr;
import javax.servlet.ServletException;
import javax.servlet.annotation.ServletSecurity.TransportGuarantee;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;


/**
 * This is the main entry point to webapp-runner. Helpers are called to parse the arguments.
 * Tomcat configuration and launching takes place here.
 *
 */
public class Main {

    private static final String AUTH_ROLE = "user";

    public static void main(String[] args) throws Exception {

        CommandLineParams commandLineParams = new CommandLineParams();

        JCommander jCommander = new JCommander(commandLineParams, args);

        if (commandLineParams.help) {
            jCommander.usage();
            System.exit(1);
        }

        // default to src/main/webapp
        if (commandLineParams.paths.size() == 0) {
            commandLineParams.paths.add("src/main/webapp");
        }

        final Tomcat tomcat = new Tomcat();

        // set directory for temp files
        tomcat.setBaseDir(resolveTomcatBaseDir(commandLineParams.port));

        // initialize the connector
        Connector nioConnector = new Connector("org.apache.coyote.http11.Http11NioProtocol");
        nioConnector.setPort(commandLineParams.port);

        if (commandLineParams.forceHTTPS) {
            nioConnector.setScheme("https");
            nioConnector.setSecure(true);
            nioConnector.setProxyPort(443);
        }

        if (commandLineParams.enableSSL) {
            nioConnector.setSecure(true);
            nioConnector.setProperty("SSLEnabled", "true");
            String pathToTrustStore = System.getProperty("javax.net.ssl.trustStore");
            if (pathToTrustStore != null) {
                nioConnector.setProperty("sslProtocol", "tls");
                File truststoreFile = new File(pathToTrustStore);
                nioConnector.setAttribute("truststoreFile", truststoreFile.getAbsolutePath());
                System.out.println(truststoreFile.getAbsolutePath());
                nioConnector.setAttribute("trustStorePassword", System.getProperty("javax.net.ssl.trustStorePassword"));
            }
            String pathToKeystore = System.getProperty("javax.net.ssl.keyStore");
            if (pathToKeystore != null) {
                File keystoreFile = new File(pathToKeystore);
                nioConnector.setAttribute("keystoreFile", keystoreFile.getAbsolutePath());
                System.out.println(keystoreFile.getAbsolutePath());
                nioConnector.setAttribute("keystorePass", System.getProperty("javax.net.ssl.keyStorePassword"));
            }
            if (commandLineParams.enableClientAuth) {
                nioConnector.setAttribute("clientAuth", true);
            }
        }

        if (commandLineParams.enableCompression) {
            nioConnector.setProperty("compression", "on");
            nioConnector.setProperty("compressableMimeType", commandLineParams.compressableMimeTypes);
        }

        if (commandLineParams.uriEncoding != null) {
            nioConnector.setURIEncoding(commandLineParams.uriEncoding);
        }

        tomcat.setConnector(nioConnector);

        tomcat.getService().addConnector(tomcat.getConnector());

        tomcat.setPort(commandLineParams.port);


        for (int i = 0; i < commandLineParams.paths.size(); i++) {
            final String path = commandLineParams.paths.get(i);
            final File war = new File(path);

            final String ctxName = commandLineParams.contextPath != null && i < commandLineParams.contextPath.size() ? commandLineParams.contextPath.get(i) : "";
            final boolean expandWar = commandLineParams.expandWar;
            final String ctxXml = commandLineParams.contextXml != null && i < commandLineParams.contextXml.size() ? commandLineParams.contextXml.get(i) : null;

            if (!war.exists()) {
                throw new FileNotFoundException("File " + path + " not found");
            }

            final Context ctx = createContext(tomcat, war, ctxName.equals("/") ? "" : ctxName, expandWar, ctxXml);

            if (!commandLineParams.shutdownOverride) {
                // allow Tomcat to shutdown if a context failure is detected
                ctx.addLifecycleListener(new LifecycleListener() {
                    public void lifecycleEvent(LifecycleEvent event) {
                        if (event.getLifecycle().getState() == LifecycleState.FAILED) {
                            Server server = tomcat.getServer();
                            if (server instanceof StandardServer) {
                                System.err.println("SEVERE: Context [" + ctxName + "] failed in [" + event.getLifecycle().getClass().getName() + "] lifecycle. Allowing Tomcat to shutdown.");
                                ((StandardServer) server).stopAwait();
                            }
                        }
                    }
                });
            }


            //set the session timeout
            if (commandLineParams.sessionTimeout != null) {
                ctx.setSessionTimeout(commandLineParams.sessionTimeout);
            }


            // set the session manager
            if (commandLineParams.sessionStore != null) {
                SessionStore.getInstance(commandLineParams.sessionStore).configureSessionStore(commandLineParams, ctx);
            }

            if (commandLineParams.enableBasicAuth) {
                enableBasicAuth(ctx, commandLineParams.enableSSL);
            }
            System.out.println(" ====== Context configured =====");
            System.out.println("war path = " + path);
            System.out.println("context path = " + ctxName);
            System.out.println("context xml = " + ctxXml);
            System.out.println(" ====== ================== =====");
        }


        addShutdownHook(tomcat);

        if (commandLineParams.enableBasicAuth || commandLineParams.tomcatUsersLocation != null) {
            tomcat.enableNaming();
        }


        //start the server
        tomcat.start();

        /*
         * NamingContextListener.lifecycleEvent(LifecycleEvent event)
         * cannot initialize GlobalNamingContext for Tomcat until
         * the Lifecycle.CONFIGURE_START_EVENT occurs, so this block 
         * must sit after the call to tomcat.start() and it requires
         * tomcat.enableNaming() to be called much earlier in the code.
         */
        if (commandLineParams.enableBasicAuth || commandLineParams.tomcatUsersLocation != null) {
            configureUserStore(tomcat, commandLineParams);
        }

        commandLineParams = null;

        tomcat.getServer().await();
    }

    private static Context createContext(final Tomcat tomcat, final File war, final String ctxName, final boolean expandWar, final String ctxXml) throws IOException, ServletException {
        final Context ctx;
        if (!war.exists()) {
            throw new RuntimeException("The specified path \"" + war.getAbsolutePath() + "\" does not exist.");
        }

        // Use the commandline context-path (or default)
        // warn if the contextPath doesn't start with a '/'. This causes issues serving content at the context root.
        if (ctxName.length() > 0 && !ctxName.startsWith("/")) {
            System.out.println("WARNING: You entered a path: [" + ctxName + "]. Your path should start with a '/'. Tomcat will update this for you, but you may still experience issues.");
        }


        if (expandWar && war.isFile()) {
            File appBase = new File(System.getProperty(Globals.CATALINA_BASE_PROP), tomcat.getHost().getAppBase());
            if (appBase.exists()) {
                appBase.delete();
            }
            appBase.mkdir();
            URL fileUrl = new URL("jar:" + war.toURI().toURL() + "!/");
            String expandedDir = ExpandWar.expand(tomcat.getHost(), fileUrl, "/expanded");
            System.out.println("Expanding " + war.getName() + " into " + expandedDir);

            System.out.println("Adding Context " + ctxName + " for " + expandedDir);
            ctx = tomcat.addWebapp(ctxName, expandedDir);
        } else {
            System.out.println("Adding Context " + ctxName + " for " + war.getPath());
            ctx = tomcat.addWebapp(ctxName, war.getAbsolutePath());
        }

        if (ctxXml != null) {
            System.out.println("Using context config: " + ctxXml);
            ctx.setConfigFile(new File(ctxXml).toURI().toURL());
        }

        return ctx;
    }

    /**
     * Gets or creates temporary Tomcat base directory within target dir
     *
     * @param port port of web process
     * @return absolute dir path
     * @throws IOException if dir fails to be created
     */
    static String resolveTomcatBaseDir(Integer port) throws IOException {
        final File baseDir = new File(System.getProperty("user.dir") + "/target/tomcat." + port);
        new File(baseDir, "webapps").mkdirs();

        if (!baseDir.isDirectory() && !baseDir.mkdirs()) {
            throw new IOException("Could not create temp dir: " + baseDir);
        }

        try {
            return baseDir.getCanonicalPath();
        } catch (IOException e) {
            return baseDir.getAbsolutePath();
        }
    }

    /*
     * Set up basic auth security on the entire application
     */
    static void enableBasicAuth(Context ctx, boolean enableSSL) {
        LoginConfig loginConfig = new LoginConfig();
        loginConfig.setAuthMethod("BASIC");
        ctx.setLoginConfig(loginConfig);
        ctx.addSecurityRole(AUTH_ROLE);

        SecurityConstraint securityConstraint = new SecurityConstraint();
        securityConstraint.addAuthRole(AUTH_ROLE);
        if (enableSSL) {
            securityConstraint.setUserConstraint(TransportGuarantee.CONFIDENTIAL.toString());
        }
        SecurityCollection securityCollection = new SecurityCollection();
        securityCollection.addPattern("/*");
        securityConstraint.addCollection(securityCollection);
        ctx.addConstraint(securityConstraint);
    }

    static void configureUserStore(final Tomcat tomcat, final CommandLineParams commandLineParams) throws Exception {
        String tomcatUsersLocation = commandLineParams.tomcatUsersLocation;
        if (tomcatUsersLocation == null) {
            tomcatUsersLocation = "../../tomcat-users.xml";
        }

        javax.naming.Reference ref = new javax.naming.Reference("org.apache.catalina.UserDatabase");
        ref.add(new StringRefAddr("pathname", tomcatUsersLocation));
        MemoryUserDatabase memoryUserDatabase =
                (MemoryUserDatabase) new MemoryUserDatabaseFactory().getObjectInstance(
                        ref,
                        new CompositeName("UserDatabase"),
                        null,
                        null);

        // Add basic auth user
        if (commandLineParams.basicAuthUser != null && commandLineParams.basicAuthPw != null) {

            memoryUserDatabase.setReadonly(false);
            Role user = memoryUserDatabase.createRole(AUTH_ROLE, AUTH_ROLE);
            memoryUserDatabase.createUser(
                    commandLineParams.basicAuthUser,
                    commandLineParams.basicAuthPw,
                    commandLineParams.basicAuthUser).addRole(user);
            memoryUserDatabase.save();

        } else if (System.getenv("BASIC_AUTH_USER") != null && System.getenv("BASIC_AUTH_PW") != null) {

            memoryUserDatabase.setReadonly(false);
            Role user = memoryUserDatabase.createRole(AUTH_ROLE, AUTH_ROLE);
            memoryUserDatabase.createUser(
                    System.getenv("BASIC_AUTH_USER"),
                    System.getenv("BASIC_AUTH_PW"),
                    System.getenv("BASIC_AUTH_USER")).addRole(user);
            memoryUserDatabase.save();
        }

        // Register memoryUserDatabase with GlobalNamingContext
        System.out.println("MemoryUserDatabase: " + memoryUserDatabase);
        tomcat.getServer().getGlobalNamingContext().addToEnvironment("UserDatabase", memoryUserDatabase);

        org.apache.catalina.deploy.ContextResource ctxRes =
                new org.apache.catalina.deploy.ContextResource();
        ctxRes.setName("UserDatabase");
        ctxRes.setAuth("Container");
        ctxRes.setType("org.apache.catalina.UserDatabase");
        ctxRes.setDescription("User database that can be updated and saved");
        ctxRes.setProperty("factory", "org.apache.catalina.users.MemoryUserDatabaseFactory");
        ctxRes.setProperty("pathname", tomcatUsersLocation);
        tomcat.getServer().getGlobalNamingResources().addResource(ctxRes);
        tomcat.getEngine().setRealm(new org.apache.catalina.realm.UserDatabaseRealm());
    }

    /**
     * Stops the embedded Tomcat server.
     */
    static void addShutdownHook(final Tomcat tomcat) {

        // add shutdown hook to stop server
        Runtime.getRuntime().addShutdownHook(new Thread() {
            public void run() {
                try {
                    if (tomcat != null) {
                        tomcat.getServer().stop();
                    }
                } catch (LifecycleException exception) {
                    throw new RuntimeException("WARNING: Cannot Stop Tomcat " + exception.getMessage(), exception);
                }
            }
        });
    }
}
