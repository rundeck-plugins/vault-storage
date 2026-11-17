package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.api.Auth;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LookupResponse;
import org.junit.Test;
import org.mockito.ArgumentMatchers;

import java.util.Properties;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * When {@code lookup()} decides to log in again, based on the TTL that lookup-self reports.
 * With the settings below the guaranteed validity is 5 * (2 + 2 + 1) = 25 seconds.
 */
public class VaultStoragePluginTokenTtlTest {

    private VaultClientProvider vaultClientProvider;

    private VaultStoragePlugin pluginWithTokenTtl(long ttl) throws Exception {
        VaultStoragePlugin plugin = spy(new VaultStoragePlugin());
        plugin.maxRetries = "5";
        plugin.readTimeout = "2";
        plugin.openTimeout = "2";
        plugin.retryIntervalMilliseconds = "1000";

        LookupResponse lookupSelf = mock(LookupResponse.class);
        doReturn(ttl).when(lookupSelf).getTTL();
        Auth auth = mock(Auth.class);
        doReturn(lookupSelf).when(auth).lookupSelf();
        Vault vault = mock(Vault.class);
        doReturn(auth).when(vault).auth();
        doReturn(mock(Logical.class)).when(vault).logical();

        vaultClientProvider = mock(VaultClientProvider.class);
        doReturn(vault).when(vaultClientProvider).getVaultClient();
        doReturn(vaultClientProvider).when(plugin).getVaultClientProvider(ArgumentMatchers.any(Properties.class));
        return plugin;
    }

    /** Vault reports ttl=0 for tokens that never expire, such as root tokens. */
    @Test
    public void nonExpiringToken_isNotRefreshed() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(0L);

        plugin.lookup();
        plugin.lookup();

        //only the initial login
        verify(vaultClientProvider, times(1)).getVaultClient();
    }

    @Test
    public void tokenWithPlentyOfTimeLeft_isNotRefreshed() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(1312L);

        plugin.lookup();
        plugin.lookup();

        verify(vaultClientProvider, times(1)).getVaultClient();
    }

    @Test
    public void tokenAboutToExpire_isRefreshed() throws Exception {
        VaultStoragePlugin plugin = pluginWithTokenTtl(20L);

        plugin.lookup();

        //the initial login plus the refresh
        verify(vaultClientProvider, times(2)).getVaultClient();
    }
}
