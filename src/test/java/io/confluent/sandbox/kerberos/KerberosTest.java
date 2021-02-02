package io.confluent.sandbox.kerberos;

import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import static org.assertj.core.api.Assertions.*;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.sasl.*;
import java.io.File;
import java.lang.reflect.Proxy;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;
import java.util.Collections;
import java.util.concurrent.Callable;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class KerberosTest {

    private SimpleKdcServer kdcServer;

    @BeforeAll
    public void beforeAll() throws Exception {

        System.setProperty("java.security.auth.login.config", "src/test/resources/test.jaas");

        kdcServer = new SimpleKdcServer();

        kdcServer.init();

        kdcServer.createAndExportPrincipals(new File("target/client.keytab"), "test");
        kdcServer.createAndExportPrincipals(new File("target/server.keytab"), "test/instance-0", "test/loadbalancer");

        kdcServer.start();
    }

    @AfterAll
    public void afterAll() throws Exception {
        kdcServer.stop();
    }

    /**
     * This is how Kafka builds client and server authenticators. The server is limited to single
     * sever instance even if the keytab may contain arbitrary number of entries.
     */
    @Test
    public void testClientBrokerAgainstInstance() throws Exception {

        LoginContext serverContext = new LoginContext("TestBroker");
        serverContext.login();
        SaslServer saslServer = impersonate(
                serverContext.getSubject(),
                doAs(serverContext.getSubject(), ()->Sasl.createSaslServer(
                        "GSSAPI",
                        "test", // service principal first part
                        "instance-0", // service principal second part
                        Collections.emptyMap(),
                        this::handleServerCallbacks
                )),
                SaslServer.class);

        LoginContext clientContext = new LoginContext("TestClient");
        clientContext.login();

        SaslClient saslClient = impersonate(
                clientContext.getSubject(),
                doAs(clientContext.getSubject(), ()->Sasl.createSaslClient(
                        new String[]{"GSSAPI"},
                        "test", // this is client principal name
                        "test", // protocol, serverName
                        "instance-0", // target server
                        Collections.emptyMap(),
                        this::handleClientCallbacks
                )),
                SaslClient.class);

        assertThatCode(
                ()->handleAuthentication(saslClient, saslServer)
        ).doesNotThrowAnyException();

    }

    /**
     * When the broker may be accessed using multiple hostnames (for example instance and load balancer),
     * the procedure fails.
     */
    @Test
    public void testClientBrokerAgainstLB() throws Exception {

        LoginContext serverContext = new LoginContext("TestBroker");
        serverContext.login();
        SaslServer saslServer = impersonate(
                serverContext.getSubject(),
                doAs(serverContext.getSubject(), ()->Sasl.createSaslServer(
                        "GSSAPI",
                        "test", // service principal first part
                        "instance-0", // service principal second part
                        Collections.emptyMap(),
                        this::handleServerCallbacks
                )),
                SaslServer.class);

        LoginContext clientContext = new LoginContext("TestClient");
        clientContext.login();

        SaslClient saslClient = impersonate(
                clientContext.getSubject(),
                doAs(clientContext.getSubject(), ()->Sasl.createSaslClient(
                        new String[]{"GSSAPI"},
                        "test", // this is client principal name
                        "test", // protocol, serverName
                        "loadbalancer", // if we have load-balanced endpoint
                        Collections.emptyMap(),
                        this::handleClientCallbacks
                )),
                SaslClient.class);

        assertThatCode(
                ()->handleAuthentication(saslClient, saslServer)
        ).isInstanceOf(Exception.class);

    }

    /**
     * Kafka uses same JAAS entry for client and server in the broker.
     */
    @Test
    public void testBrokerBroker() throws Exception {

        LoginContext serverContext = new LoginContext("TestBroker");
        serverContext.login();
        SaslServer saslServer = impersonate(
                serverContext.getSubject(),
                doAs(serverContext.getSubject(), ()->Sasl.createSaslServer(
                        "GSSAPI",
                        "test", // service principal first part
                        "instance-0", // service principal second part
                        Collections.emptyMap(),
                        this::handleServerCallbacks
                )),
                SaslServer.class);

        LoginContext clientContext = new LoginContext("TestBroker");
        clientContext.login();

        SaslClient saslClient = impersonate(
                clientContext.getSubject(),
                doAs(clientContext.getSubject(), ()->Sasl.createSaslClient(
                        new String[]{"GSSAPI"},
                        "test", // this is client principal name
                        "test", // protocol, serverName
                        "instance-0", // target server
                        Collections.emptyMap(),
                        this::handleClientCallbacks
                )),
                SaslClient.class);

        assertThatCode(
                ()->handleAuthentication(saslClient, saslServer)
        ).doesNotThrowAnyException();

    }

    /**
     * This is how it should be implemented.
     */
    @Test
    public void testClientServerAgainstInstance() throws Exception {

        LoginContext serverContext = new LoginContext("TestServer");
        serverContext.login();
        SaslServer saslServer = impersonate(
                serverContext.getSubject(),
                doAs(serverContext.getSubject(), ()->Sasl.createSaslServer(
                        "GSSAPI",
                        "test", // this is first part of SPN
                        // we do not limit to specific server, but JAAS definition must contain:
                        // principal="*"
                        // isInitiator=false
                        null,
                        Collections.emptyMap(),
                        this::handleServerCallbacks
                )),
                SaslServer.class);

        LoginContext clientContext = new LoginContext("TestClient");
        clientContext.login();

        SaslClient saslClient = impersonate(
                clientContext.getSubject(),
                doAs(clientContext.getSubject(), ()->Sasl.createSaslClient(
                        new String[]{"GSSAPI"},
                        "test", // this UPN
                        "test", // first part of SPN
                        "instance-0", // and server
                        Collections.emptyMap(),
                        this::handleClientCallbacks
                )),
                SaslClient.class);

        assertThatCode(
                ()->handleAuthentication(saslClient, saslServer)
        ).doesNotThrowAnyException();

    }

    /**
     * Same config as above; the only difference is the server name which in this case is LB
     */
    @Test
    public void testClientServerAgainstLB() throws Exception {

        LoginContext serverContext = new LoginContext("TestServer");
        serverContext.login();
        SaslServer saslServer = impersonate(
                serverContext.getSubject(),
                doAs(serverContext.getSubject(), ()->Sasl.createSaslServer(
                        "GSSAPI",
                        "test",
                        null,
                        Collections.emptyMap(),
                        this::handleServerCallbacks
                )),
                SaslServer.class);

        LoginContext clientContext = new LoginContext("TestClient");
        clientContext.login();

        SaslClient saslClient = impersonate(
                clientContext.getSubject(),
                doAs(clientContext.getSubject(), ()->Sasl.createSaslClient(
                        new String[]{"GSSAPI"},
                        "test",
                        "test",
                        "loadbalancer", // changed
                        Collections.emptyMap(),
                        this::handleClientCallbacks
                )),
                SaslClient.class);

        assertThatCode(
                ()->handleAuthentication(saslClient, saslServer)
        ).doesNotThrowAnyException();

    }

    // ---- utilities ----

    /**
     * Execute sequence of challenge-response until client reports complete.
     */
    private void handleAuthentication(SaslClient saslClient, SaslServer saslServer) throws Exception {
        byte[] serverToken = new byte[]{};
        byte[] clientToken;
        while (!saslClient.isComplete()) {
            clientToken = saslClient.evaluateChallenge(serverToken);
            serverToken = saslServer.evaluateResponse(clientToken);
        }
    }

    /**
     * Wraps the target instance that all the methods are called in the security context of subject.
     */
    private <T> T impersonate(Subject subject, T target, Class<T> iface) {
        return (T)Proxy.newProxyInstance(
                iface.getClassLoader(),
                new Class[]{iface},
                (proxy, method, args)-> doAs(subject, ()->method.invoke(target, args))
        );
    }

    private <T> T doAs(final Subject subject, final Callable<T> action) throws Exception {
        return Subject.doAs(subject, (PrivilegedExceptionAction<T>)()->action.call());
    }

    private void handleServerCallbacks(Callback[] callbacks) throws UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof RealmCallback) {
                RealmCallback rc = (RealmCallback) callback;
                rc.setText(rc.getDefaultText());
            } else if (callback instanceof AuthorizeCallback) {
                AuthorizeCallback ac = (AuthorizeCallback) callback;
                ac.setAuthorized(true);
                ac.setAuthorizedID(ac.getAuthenticationID());
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    private void handleClientCallbacks(Callback[] callbacks) throws UnsupportedCallbackException {
        Subject subject = Subject.getSubject(AccessController.getContext());
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                NameCallback nc = (NameCallback) callback;
                if (subject != null && !subject.getPublicCredentials(String.class).isEmpty()) {
                    nc.setName(subject.getPublicCredentials(String.class).iterator().next());
                } else {
                    nc.setName(nc.getDefaultName());
                }
            } else if (callback instanceof PasswordCallback) {
                if (subject != null && !subject.getPrivateCredentials(String.class).isEmpty()) {
                    char[] password = subject.getPrivateCredentials(String.class).iterator().next().toCharArray();
                    ((PasswordCallback) callback).setPassword(password);
                } else {
                    throw new UnsupportedCallbackException(callback, "Password not available");
                }
            } else if (callback instanceof RealmCallback) {
                RealmCallback rc = (RealmCallback) callback;
                rc.setText(rc.getDefaultText());
            } else if (callback instanceof AuthorizeCallback) {
                AuthorizeCallback ac = (AuthorizeCallback) callback;
                String authId = ac.getAuthenticationID();
                String authzId = ac.getAuthorizationID();
                ac.setAuthorized(authId.equals(authzId));
                if (ac.isAuthorized())
                    ac.setAuthorizedID(authzId);
            } else {
                throw new UnsupportedCallbackException(callback, "Unrecognized SASL ClientCallback");
            }
        }
    }

}
