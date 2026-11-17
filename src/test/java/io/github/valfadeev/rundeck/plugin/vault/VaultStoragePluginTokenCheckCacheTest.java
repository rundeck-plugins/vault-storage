package io.github.valfadeev.rundeck.plugin.vault;

import com.dtolabs.rundeck.core.storage.ResourceMeta;
import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Auth;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.response.LookupResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
import org.rundeck.storage.api.Path;
import org.rundeck.storage.api.PathUtil;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Reads trust a successful lookup-self result for a short while instead of calling Vault before
 * every single key; lists and writes always check the token. With the settings below the
 * guaranteed validity is 25 seconds.
 */
public class VaultStoragePluginTokenCheckCacheTest {

    private static final Path KEY = PathUtil.asPath("keys/test");

    private Auth auth;
    private Vault vault;
    private VaultClientProvider vaultClientProvider;
    private long nowNanos = 1_000L;

    private static RestResponse status(int status) {
        RestResponse restResponse = mock(RestResponse.class);
        doReturn(status).when(restResponse).getStatus();
        return restResponse;
    }

    /** A Vault client whose reads all answer with the given status and data. */
    private static Vault vaultWhoseReadsReturn(Auth auth, int status, Map<String, String> data) throws Exception {
        LogicalResponse read = mock(LogicalResponse.class);
        doReturn(status(status)).when(read).getRestResponse();
        doReturn(data).when(read).getData();

        LogicalResponse list = mock(LogicalResponse.class);
        doReturn(status(200)).when(list).getRestResponse();
        doReturn(Collections.singletonList("test")).when(list).getListData();

        LogicalResponse write = mock(LogicalResponse.class);
        doReturn(status(204)).when(write).getRestResponse();

        Logical logical = mock(Logical.class);
        doReturn(read).when(logical).read(ArgumentMatchers.anyString());
        doReturn(list).when(logical).list(ArgumentMatchers.anyString());
        doReturn(write).when(logical).write(ArgumentMatchers.anyString(), ArgumentMatchers.anyMap());

        Vault vault = mock(Vault.class);
        doReturn(auth).when(vault).auth();
        doReturn(logical).when(vault).logical();
        return vault;
    }

    private static Map<String, String> storedSecret() {
        Map<String, String> stored = new HashMap<>();
        stored.put("value", "s3cret");
        return stored;
    }

    private VaultStoragePlugin pluginWithTokenTtl(long ttl) throws Exception {
        VaultStoragePlugin plugin = spy(new VaultStoragePlugin());
        plugin.maxRetries = "5";
        plugin.readTimeout = "2";
        plugin.openTimeout = "2";
        plugin.retryIntervalMilliseconds = "1000";
        plugin.nanoClock = () -> nowNanos;

        LookupResponse lookupSelf = mock(LookupResponse.class);
        doReturn(ttl).when(lookupSelf).getTTL();
        auth = mock(Auth.class);
        doReturn(lookupSelf).when(auth).lookupSelf();
        vault = vaultWhoseReadsReturn(auth, 200, storedSecret());

        vaultClientProvider = mock(VaultClientProvider.class);
        doReturn(vault).when(vaultClientProvider).getVaultClient();
        doReturn(vaultClientProvider).when(plugin).getVaultClientProvider(ArgumentMatchers.any(Properties.class));
        return plugin;
    }

    private void advanceSeconds(long seconds) {
        nowNanos += TimeUnit.SECONDS.toNanos(seconds);
    }

    @Test
    public void repeatedReadsWithinTheWindowCheckTheTokenOnce() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);

        for (int i = 0; i < 50; i++) {
            assertFalse(plugin.getVaultObject(KEY).isError());
        }

        verify(auth, times(1)).lookupSelf();
        verify(vault.logical(), times(50)).read(ArgumentMatchers.anyString());
    }

    @Test
    public void readChecksTheTokenAgainOnceTheWindowHasPassed() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);

        plugin.getVaultObject(KEY);
        advanceSeconds(VaultStoragePlugin.MAX_TOKEN_CHECK_VALIDITY_SECONDS - 1);
        plugin.getVaultObject(KEY);
        verify(auth, times(1)).lookupSelf();

        advanceSeconds(1);
        plugin.getVaultObject(KEY);
        verify(auth, times(2)).lookupSelf();
    }

    @Test
    public void nonExpiringTokenIsAlsoCheckedAgainAfterTheWindow() throws Exception {
        //ttl=0: the token does not expire, but it can still be revoked
        VaultStoragePlugin plugin = pluginWithTokenTtl(0L);

        plugin.getVaultObject(KEY);
        plugin.getVaultObject(KEY);
        verify(auth, times(1)).lookupSelf();

        advanceSeconds(VaultStoragePlugin.MAX_TOKEN_CHECK_VALIDITY_SECONDS);
        plugin.getVaultObject(KEY);
        verify(auth, times(2)).lookupSelf();
    }

    @Test
    public void windowNeverReachesPastThePointWhereTheTokenNeedsRefreshing() throws Exception {
        //ttl 28s, guaranteed validity 25s: the token must be looked at again within 3 seconds
        VaultStoragePlugin plugin = pluginWithTokenTtl(28L);

        plugin.getVaultObject(KEY);
        advanceSeconds(2);
        plugin.getVaultObject(KEY);
        verify(auth, times(1)).lookupSelf();

        advanceSeconds(1);
        plugin.getVaultObject(KEY);
        verify(auth, times(2)).lookupSelf();
    }

    @Test
    public void tokenThatNeededRefreshingIsNotTrusted() throws Exception {
        //ttl below the guaranteed validity: every read logs in again and nothing is remembered
        VaultStoragePlugin plugin = pluginWithTokenTtl(20L);

        plugin.getVaultObject(KEY);
        plugin.getVaultObject(KEY);

        verify(auth, times(2)).lookupSelf();
        //the initial login plus one refresh per read
        verify(vaultClientProvider, times(3)).getVaultClient();
    }

    @Test
    public void failedLookupIsNotRemembered() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);
        doThrow(new VaultException("Vault is down", 503)).when(auth).lookupSelf();

        plugin.getVaultObject(KEY);
        plugin.getVaultObject(KEY);

        verify(auth, times(2)).lookupSelf();
    }

    /** Only reads skip the check: a list always asks Vault first, as before. */
    @Test
    public void listsAlwaysCheckTheToken() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);

        plugin.getVaultObject(KEY);
        verify(auth, times(1)).lookupSelf();

        assertTrue(plugin.hasDirectory("keys"));
        assertTrue(plugin.hasDirectory("keys"));
        verify(auth, times(3)).lookupSelf();
    }

    /** A write always asks Vault first; the read-back that follows it relies on that check. */
    @Test
    public void writesAlwaysCheckTheToken() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);
        ResourceMeta content = mock(ResourceMeta.class);
        doReturn(new HashMap<String, String>()).when(content).getMeta();

        plugin.getVaultObject(KEY);
        verify(auth, times(1)).lookupSelf();

        plugin.createResource(KEY, content);
        verify(auth, times(2)).lookupSelf();
        verify(vault.logical(), times(1)).write(ArgumentMatchers.anyString(), ArgumentMatchers.anyMap());
    }

    /**
     * The token is revoked while its last check is still trusted: the read fails, which makes the
     * plugin check the token straight away, log in again and repeat the read.
     */
    @Test
    public void readThatFailsOnATrustedTokenChecksTheTokenAndRetriesAfterANewLogin() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);

        LookupResponse healthy = mock(LookupResponse.class);
        doReturn(3600L).when(healthy).getTTL();
        Auth revokedAuth = mock(Auth.class);
        doReturn(healthy).doThrow(new VaultException("permission denied", 403)).when(revokedAuth).lookupSelf();

        Vault revoked = vaultWhoseReadsReturn(revokedAuth, 403, Collections.emptyMap());
        doReturn(revoked, vault).when(vaultClientProvider).getVaultClient();

        //first read: checks the token (still healthy), then fails with 403 and stays failed
        plugin.getVaultObject(KEY);
        //second read: the check is trusted, the read fails, the token is checked again -> new login
        KeyObject object = plugin.getVaultObject(KEY);

        assertFalse("the read must succeed after the new login", object.isError());
        verify(vaultClientProvider, times(2)).getVaultClient();
    }

    /** A key that simply does not exist costs one token check, not a second read. */
    @Test
    public void readOfAMissingKeyOnATrustedTokenIsNotRepeated() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);
        Vault missing = vaultWhoseReadsReturn(auth, 404, Collections.emptyMap());
        doReturn(missing).when(vaultClientProvider).getVaultClient();

        plugin.getVaultObject(KEY);
        KeyObject object = plugin.getVaultObject(KEY);

        assertTrue(object.isError());
        verify(vaultClientProvider, times(1)).getVaultClient();
        //two reads of the key and two of its parent path: nothing is read twice within one call
        verify(missing.logical(), times(4)).read(ArgumentMatchers.anyString());
    }
}
