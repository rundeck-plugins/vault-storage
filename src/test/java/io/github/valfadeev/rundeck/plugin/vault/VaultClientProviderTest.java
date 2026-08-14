package io.github.valfadeev.rundeck.plugin.vault;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import com.sun.net.httpserver.HttpServer;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import org.junit.Test;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

public class VaultClientProviderTest {

    @Test
    public void getVaultConfigTest() throws Exception {
        Properties configuration = new Properties();

        InputStream resourceStream = getClass()
                .getResourceAsStream("rundeck-config.properties");

        configuration.load(resourceStream);

        VaultConfig config = new VaultClientProvider(configuration)
                .getVaultConfig();

        assertThat(config.getAddress(), is("http://localhost:8200"));
        assertThat(config.getNameSpace(), is("namespace1"));
        assertThat(config.getSslConfig().isVerify(), is(false));
        assertThat(config.getOpenTimeout(), is(5));
        assertThat(config.getReadTimeout(), is(20));
    }

    /**
     * When {@code certRoleName} is configured, the cert auth login request must carry the
     * Vault cert auth API's optional {@code name} parameter (see
     * https://developer.hashicorp.com/vault/api-docs/auth/cert#login-with-tls-certificate-method)
     * so Vault deployments requiring an explicit certificate role can be authenticated against.
     */
    @Test
    public void certAuthWithRoleNameSendsNameInLoginRequestBody() throws Exception {
        final String[] capturedPath = new String[1];
        final String[] capturedBody = new String[1];

        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/v1/auth/tls-auth/login", exchange -> {
            capturedPath[0] = exchange.getRequestURI().getPath();
            capturedBody[0] = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

            byte[] response = ("{\"auth\":{\"client_token\":\"s.faketoken\",\"renewable\":false,"
                    + "\"lease_duration\":0,\"policies\":[\"default\"]},\"renewable\":false}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();

        try {
            Properties configuration = new Properties();
            configuration.setProperty("address", "http://localhost:" + server.getAddress().getPort());
            configuration.setProperty("authBackend", "cert");
            configuration.setProperty("certAuthMount", "tls-auth");
            configuration.setProperty("certRoleName", "app-01693-lseg-enterprise-rundeck");
            configuration.setProperty("validateSsl", "false");
            configuration.setProperty("maxRetries", "0");
            configuration.setProperty("retryIntervalMilliseconds", "0");
            configuration.setProperty("openTimeout", "5");
            configuration.setProperty("readTimeout", "5");
            configuration.setProperty("engineVersion", "1");

            Vault vault = new VaultClientProvider(configuration).getVaultClient();

            assertThat(vault, is(notNullValue()));
            assertThat(capturedPath[0], is("/v1/auth/tls-auth/login"));
            assertThat(capturedBody[0], is("{\"name\":\"app-01693-lseg-enterprise-rundeck\"}"));
        } finally {
            server.stop(0);
        }
    }

    /**
     * Backward compatibility: when {@code certRoleName} is not set, no request body is sent at
     * all (the plugin falls back to the vault-java-driver's own {@code loginByCert}, which relies
     * solely on the mTLS handshake to identify the client).
     */
    @Test
    public void certAuthWithoutRoleNameSendsNoBody() throws Exception {
        final String[] capturedBody = new String[1];
        final boolean[] requestReceived = new boolean[1];

        HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/v1/auth/cert/login", exchange -> {
            requestReceived[0] = true;
            capturedBody[0] = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);

            byte[] response = ("{\"auth\":{\"client_token\":\"s.faketoken\",\"renewable\":false,"
                    + "\"lease_duration\":0,\"policies\":[\"default\"]},\"renewable\":false}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();

        try {
            Properties configuration = new Properties();
            configuration.setProperty("address", "http://localhost:" + server.getAddress().getPort());
            configuration.setProperty("authBackend", "cert");
            configuration.setProperty("validateSsl", "false");
            configuration.setProperty("maxRetries", "0");
            configuration.setProperty("retryIntervalMilliseconds", "0");
            configuration.setProperty("openTimeout", "5");
            configuration.setProperty("readTimeout", "5");
            configuration.setProperty("engineVersion", "1");

            Vault vault = new VaultClientProvider(configuration).getVaultClient();

            assertThat(vault, is(notNullValue()));
            assertThat(requestReceived[0], is(true));
            assertThat(capturedBody[0], is(""));
        } finally {
            server.stop(0);
        }
    }
}
