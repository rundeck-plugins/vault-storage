package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Auth;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LookupResponse;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import org.junit.Test;
import org.mockito.ArgumentMatchers;
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
 * {@code lookup()} trusts a successful lookup-self result for a short while instead of calling
 * Vault before every read. With the settings below the guaranteed validity is 25 seconds.
 */
public class VaultStoragePluginTokenCheckCacheTest {

    private Auth auth;
    private VaultClientProvider vaultClientProvider;
    private long nowNanos = 1_000L;

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
        Vault vault = mock(Vault.class);
        doReturn(auth).when(vault).auth();
        doReturn(mock(Logical.class)).when(vault).logical();

        vaultClientProvider = mock(VaultClientProvider.class);
        doReturn(vault).when(vaultClientProvider).getVaultClient();
        doReturn(vaultClientProvider).when(plugin).getVaultClientProvider(ArgumentMatchers.any(Properties.class));
        return plugin;
    }

    private void advanceSeconds(long seconds) {
        nowNanos += TimeUnit.SECONDS.toNanos(seconds);
    }

    @Test
    public void repeatedLookupsWithinTheWindowCallVaultOnce() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);

        for (int i = 0; i < 50; i++) {
            plugin.lookup();
        }

        verify(auth, times(1)).lookupSelf();
    }

    @Test
    public void tokenIsCheckedAgainOnceTheWindowHasPassed() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);

        plugin.lookup();
        advanceSeconds(VaultStoragePlugin.MAX_TOKEN_CHECK_VALIDITY_SECONDS - 1);
        plugin.lookup();
        verify(auth, times(1)).lookupSelf();

        advanceSeconds(1);
        plugin.lookup();
        verify(auth, times(2)).lookupSelf();
    }

    @Test
    public void nonExpiringTokenIsAlsoCheckedAgainAfterTheWindow() throws Exception {
        //ttl=0: the token does not expire, but it can still be revoked
        VaultStoragePlugin plugin = pluginWithTokenTtl(0L);

        plugin.lookup();
        plugin.lookup();
        verify(auth, times(1)).lookupSelf();

        advanceSeconds(VaultStoragePlugin.MAX_TOKEN_CHECK_VALIDITY_SECONDS);
        plugin.lookup();
        verify(auth, times(2)).lookupSelf();
    }

    @Test
    public void windowNeverReachesPastThePointWhereTheTokenNeedsRefreshing() throws Exception {
        //ttl 28s, guaranteed validity 25s: the token must be looked at again within 3 seconds
        VaultStoragePlugin plugin = pluginWithTokenTtl(28L);

        plugin.lookup();
        advanceSeconds(2);
        plugin.lookup();
        verify(auth, times(1)).lookupSelf();

        advanceSeconds(1);
        plugin.lookup();
        verify(auth, times(2)).lookupSelf();
    }

    @Test
    public void tokenThatNeededRefreshingIsNotTrusted() throws Exception {
        //ttl below the guaranteed validity: every lookup logs in again and nothing is remembered
        VaultStoragePlugin plugin = pluginWithTokenTtl(20L);

        plugin.lookup();
        plugin.lookup();

        verify(auth, times(2)).lookupSelf();
        //the initial login plus one refresh per lookup
        verify(vaultClientProvider, times(3)).getVaultClient();
    }

    @Test
    public void failedLookupIsNotRemembered() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);
        doThrow(new VaultException("Vault is down", 503)).when(auth).lookupSelf();

        plugin.lookup();
        plugin.lookup();

        verify(auth, times(2)).lookupSelf();
    }

    private static Vault vaultWhoseReadsReturn(Auth auth, int status, Map<String, String> data) throws Exception {
        RestResponse restResponse = mock(RestResponse.class);
        doReturn(status).when(restResponse).getStatus();
        LogicalResponse response = mock(LogicalResponse.class);
        doReturn(restResponse).when(response).getRestResponse();
        doReturn(data).when(response).getData();
        Logical logical = mock(Logical.class);
        doReturn(response).when(logical).read(ArgumentMatchers.anyString());

        Vault vault = mock(Vault.class);
        doReturn(auth).when(vault).auth();
        doReturn(logical).when(vault).logical();
        return vault;
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

        Map<String, String> stored = new HashMap<>();
        stored.put("value", "s3cret");
        Vault revoked = vaultWhoseReadsReturn(revokedAuth, 403, Collections.emptyMap());
        Vault fresh = vaultWhoseReadsReturn(auth, 200, stored);
        doReturn(revoked, fresh).when(vaultClientProvider).getVaultClient();

        plugin.lookup();
        KeyObject object = plugin.getVaultObject(PathUtil.asPath("keys/test"));

        assertFalse("the read must succeed after the new login", object.isError());
        verify(vaultClientProvider, times(2)).getVaultClient();
    }

    /** A key that simply does not exist costs one token check, not a second read. */
    @Test
    public void readOfAMissingKeyOnATrustedTokenIsNotRepeated() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(3600L);
        Vault vault = vaultWhoseReadsReturn(auth, 404, Collections.emptyMap());
        doReturn(vault).when(vaultClientProvider).getVaultClient();

        plugin.lookup();
        KeyObject object = plugin.getVaultObject(PathUtil.asPath("keys/missing"));

        assertTrue(object.isError());
        verify(vaultClientProvider, times(1)).getVaultClient();
        //one read of the key and one of its parent path, each done once
        verify(vault.logical(), times(2)).read(ArgumentMatchers.anyString());
    }
}
