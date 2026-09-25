package io.github.valfadeev.rundeck.plugin.vault;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.dtolabs.rundeck.core.plugins.configuration.ConfigurationException;
import com.dtolabs.rundeck.core.storage.ResourceMeta;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Auth;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LookupResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.rundeck.storage.api.PathUtil;
import org.rundeck.storage.api.StorageException;
import org.slf4j.LoggerFactory;

import static io.github.valfadeev.rundeck.plugin.vault.ConfigOptions.*;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Regression tests for what the plugin writes to the log.
 *
 * <p>The assertions read the output of the SLF4J logger the rest of the class uses: logging through
 * {@code java.util.logging} instead would leave this appender empty, because JUL output never reaches
 * Rundeck's slf4j/log4j pipeline either.
 */
public class VaultStoragePluginLoggingTest {

    private static final String SECRET = "s3cr3t-password-value";

    /** The {@link Logical} the plugin under test writes through; published by {@link #pluginWithTokenTtl}. */
    private Logical logical;

    private ch.qos.logback.classic.Logger pluginLogger;
    private ListAppender<ILoggingEvent> captured;
    private Level previousLevel;
    private boolean previousAdditive;

    @Before
    public void capturePluginLog() {
        pluginLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(VaultStoragePlugin.class);
        previousLevel = pluginLogger.getLevel();
        previousAdditive = pluginLogger.isAdditive();

        captured = new ListAppender<>();
        captured.start();
        pluginLogger.addAppender(captured);
        pluginLogger.setLevel(Level.DEBUG);
        pluginLogger.setAdditive(false);
    }

    @After
    public void releasePluginLog() {
        pluginLogger.detachAppender(captured);
        pluginLogger.setLevel(previousLevel);
        pluginLogger.setAdditive(previousAdditive);
        captured.stop();
    }

    @Test
    public void lookup_reportsProgressThroughTheSlf4jLogger() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(1312L, false);

        plugin.lookup();

        assertThat(messages(), hasItem(containsString("Finished Vault self-lookup successfully")));
    }

    @Test
    public void lookup_doesNotReportSuccessWhenTokenRefreshFails() throws Exception {
        //TTL below the guaranteed validity makes lookup() refresh the token, and that refresh fails
        VaultStoragePlugin plugin = pluginWithTokenTtl(20L, true);

        plugin.lookup();

        assertThat(messages(), hasItem(containsString("Error logging into Vault")));
        for (String message : messagesAfterLast("Logging into Vault")) {
            assertThat("no success is reported once the login failed: " + message,
                    message.toLowerCase(), not(containsString("success")));
        }
    }

    @Test
    public void lookup_propagatesUnexpectedRuntimeExceptions() throws Exception {
        //a blanket catch here would hide the failure and leave callers with a stale Vault client
        VaultStoragePlugin plugin = spy(new VaultStoragePlugin());
        doThrow(new IllegalStateException("boom")).when(plugin).getVaultClient();

        IllegalStateException thrown = assertThrows(IllegalStateException.class, plugin::lookup);

        assertThat(thrown.getMessage(), is("boom"));
    }

    @Test
    public void saveResource_logsThePayloadKeysButNeverTheSecretValues() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(1312L, false);
        doThrow(new VaultException("write not attempted in this test"))
                .when(logical).write(anyString(), anyMap());

        Map<String, String> meta = new HashMap<>();
        meta.put(VaultStoragePlugin.RUNDECK_KEY_TYPE, "private");
        meta.put(VaultStoragePlugin.RUNDECK_CONTENT_MASK, "content");

        ResourceMeta content = mock(ResourceMeta.class);
        doReturn(meta).when(content).getMeta();
        doAnswer(invocation -> {
            byte[] data = SECRET.getBytes(StandardCharsets.UTF_8);
            ((OutputStream) invocation.getArgument(0)).write(data);
            return (long) data.length;
        }).when(content).writeContent(any(OutputStream.class));

        assertThrows(StorageException.class,
                () -> plugin.createResource(PathUtil.asPath("keys/test/password"), content));

        for (String message : messages()) {
            assertThat("the secret value must never reach the log: " + message,
                    message, not(containsString(SECRET)));
        }
        assertThat("the payload keys stay in the log to keep it useful for troubleshooting",
                messages(), hasItem(allOf(containsString("Generated payload"),
                        containsString(VaultStoragePlugin.VAULT_STORAGE_KEY))));
    }

    /**
     * Plugin wired to a mocked Vault client, as in {@link VaultStoragePluginTest}: the first
     * {@code getVaultClient()} logs in and publishes the mocked {@link Logical}. When
     * {@code failTokenRefresh} is set, every later login attempt fails.
     */
    private VaultStoragePlugin pluginWithTokenTtl(long ttl, boolean failTokenRefresh) throws Exception {
        VaultStoragePlugin plugin = spy(new VaultStoragePlugin());
        Properties properties = mock(Properties.class);
        VaultClientProvider clientProvider = mock(VaultClientProvider.class);
        Vault vaultClient = mock(Vault.class);
        logical = mock(Logical.class);
        Auth auth = mock(Auth.class);
        LookupResponse lookupSelf = mock(LookupResponse.class);

        doReturn(clientProvider).when(plugin).getVaultClientProvider(properties);
        if (failTokenRefresh) {
            doReturn(vaultClient)
                    .doThrow(new ConfigurationException("login refused"))
                    .when(clientProvider).getVaultClient();
        } else {
            doReturn(vaultClient).when(clientProvider).getVaultClient();
        }
        doReturn(logical).when(vaultClient).logical();
        doReturn(auth).when(vaultClient).auth();
        doReturn(lookupSelf).when(auth).lookupSelf();
        doReturn(ttl).when(lookupSelf).getTTL();

        doReturn("5").when(properties).getProperty(VAULT_MAX_RETRIES);
        doReturn("2").when(properties).getProperty(VAULT_READ_TIMEOUT);
        doReturn("2").when(properties).getProperty(VAULT_OPEN_TIMEOUT);
        doReturn("1000").when(properties).getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS);

        plugin.properties = properties;
        plugin.getVaultClient();
        captured.list.clear();

        return plugin;
    }

    private List<String> messages() {
        List<String> messages = new ArrayList<>();
        for (ILoggingEvent event : captured.list) {
            messages.add(event.getFormattedMessage());
        }
        return messages;
    }

    private List<String> messagesAfterLast(String marker) {
        List<String> messages = messages();
        int last = -1;
        for (int i = 0; i < messages.size(); i++) {
            if (messages.get(i).contains(marker)) {
                last = i;
            }
        }
        assertTrue("expected a '" + marker + "' message in " + messages, last >= 0);
        return messages.subList(last + 1, messages.size());
    }
}
