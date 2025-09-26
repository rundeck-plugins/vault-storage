package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Auth;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LookupResponse;
import com.dtolabs.rundeck.core.plugins.configuration.ConfigurationException;
import org.junit.Test;
import org.mockito.Spy;

import java.util.Properties;

import static io.github.valfadeev.rundeck.plugin.vault.ConfigOptions.*;
import static org.mockito.Mockito.*;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

public class VaultStoragePluginTest {

    @Spy
    private VaultStoragePlugin vaultStoragePlugin = new VaultStoragePlugin();

    @Test
    public void guaranteedTokenValidity_returnsCalculatedValue() {
        Properties properties = mock(Properties.class);

        doReturn("5").when(properties).getProperty(VAULT_MAX_RETRIES);
        doReturn("2").when(properties).getProperty(VAULT_READ_TIMEOUT);
        doReturn("2").when(properties).getProperty(VAULT_OPEN_TIMEOUT);
        doReturn("1000").when(properties).getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS);

        int validity = vaultStoragePlugin.calculateGuaranteedTokenValidity(properties);

        assertThat(validity, is(25));
    }

    @Test
    public void guaranteedTokenValidity_returnMaxCapedValue() {
        Properties properties = mock(Properties.class);

        doReturn("5").when(properties).getProperty(VAULT_MAX_RETRIES);
        doReturn("20").when(properties).getProperty(VAULT_READ_TIMEOUT);
        doReturn("20").when(properties).getProperty(VAULT_OPEN_TIMEOUT);
        doReturn("1000").when(properties).getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS);

        int validity = vaultStoragePlugin.calculateGuaranteedTokenValidity(properties);

        assertThat(validity, is(VaultStoragePlugin.MAX_GUARANTEED_VALIDITY_SECONDS));
    }

    @Test
    public void lookUp_passes_when_tokenIsValid() throws ConfigurationException, VaultException {
        VaultStoragePlugin vaultStoragePlugin = spy(new VaultStoragePlugin());
        Properties properties = mock(Properties.class);
        VaultClientProvider vaultClientProvider = mock(VaultClientProvider.class);
        Vault vault = mock(Vault.class);
        Logical logical = mock(Logical.class);
        Auth auth = mock(Auth.class);
        LookupResponse response = mock(LookupResponse.class);

        doReturn(vaultClientProvider).when(vaultStoragePlugin).getVaultClientProvider(properties);
        doReturn(vault).when(vaultClientProvider).getVaultClient();
        doReturn(vault).when(vaultStoragePlugin).getVaultClient();
        doReturn(logical).when(vault).logical();

        doReturn(auth).when(vault).auth();
        doReturn(response).when(auth).lookupSelf();
        doReturn(1312L).when(response).getTTL();

        doReturn("rundeck").when(properties).getProperty(VAULT_PREFIX);
        doReturn("approle").when(properties).getProperty(VAULT_SECRET_BACKEND);
        doReturn("vault").when(properties).getProperty(VAULT_STORAGE_BEHAVIOUR);

        doReturn("5").when(properties).getProperty(VAULT_MAX_RETRIES);
        doReturn("2").when(properties).getProperty(VAULT_READ_TIMEOUT);
        doReturn("2").when(properties).getProperty(VAULT_OPEN_TIMEOUT);
        doReturn("1000").when(properties).getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS);

        clearInvocations(vaultClientProvider);

        vaultStoragePlugin.lookup();

        verify(vaultClientProvider, times(0)).getVaultClient();
    }

    @Test
    public void lookUp_refreshesToken_when_currentTokenIsAboutToExpire() throws ConfigurationException, VaultException {
        VaultStoragePlugin vaultStoragePlugin = spy(new VaultStoragePlugin());
        Properties properties = mock(Properties.class);
        VaultClientProvider vaultClientProvider = mock(VaultClientProvider.class);
        Vault vault = mock(Vault.class);
        Logical logical = mock(Logical.class);
        Auth auth = mock(Auth.class);
        LookupResponse response = mock(LookupResponse.class);

        doReturn(vaultClientProvider).when(vaultStoragePlugin).getVaultClientProvider(properties);
        doReturn(vault).when(vaultClientProvider).getVaultClient();
        doReturn(logical).when(vault).logical();

        doReturn(auth).when(vault).auth();
        doReturn(response).when(auth).lookupSelf();
        doReturn(20L).when(response).getTTL();

        doReturn("rundeck").when(properties).getProperty(VAULT_PREFIX);
        doReturn("approle").when(properties).getProperty(VAULT_SECRET_BACKEND);
        doReturn("vault").when(properties).getProperty(VAULT_STORAGE_BEHAVIOUR);

        doReturn("rundeck").when(properties).setProperty(VAULT_PREFIX, "rundeck");
        doReturn("approle").when(properties).setProperty(VAULT_SECRET_BACKEND, "approle");
        doReturn("vault").when(properties).setProperty(VAULT_STORAGE_BEHAVIOUR, "vault");

        doReturn("5").when(properties).getProperty(VAULT_MAX_RETRIES);
        doReturn("2").when(properties).getProperty(VAULT_READ_TIMEOUT);
        doReturn("2").when(properties).getProperty(VAULT_OPEN_TIMEOUT);
        doReturn("1000").when(properties).getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS);

        clearInvocations(vaultClientProvider);

        vaultStoragePlugin.properties=properties;

        vaultStoragePlugin.lookup();

        verify(vaultClientProvider, times(2)).getVaultClient();
    }

    @Test
    public void lookUp_refreshesToken_when_tokenIsExpired() throws ConfigurationException, VaultException {
        VaultStoragePlugin vaultStoragePlugin = spy(new VaultStoragePlugin());
        Properties properties = mock(Properties.class);
        VaultClientProvider vaultClientProvider = mock(VaultClientProvider.class);
        Vault vault = mock(Vault.class);
        Logical logical = mock(Logical.class);
        Auth auth = mock(Auth.class);

        doReturn(vaultClientProvider).when(vaultStoragePlugin).getVaultClientProvider(properties);
        doReturn(vault).when(vaultClientProvider).getVaultClient();
        doReturn(logical).when(vault).logical();

        doReturn(auth).when(vault).auth();
        doThrow(new VaultException("Forbidden", 403)).when(auth).lookupSelf();

        doReturn("rundeck").when(properties).getProperty(VAULT_PREFIX);
        doReturn("approle").when(properties).getProperty(VAULT_SECRET_BACKEND);
        doReturn("vault").when(properties).getProperty(VAULT_STORAGE_BEHAVIOUR);

        doReturn("rundeck").when(properties).setProperty(VAULT_PREFIX, "rundeck");
        doReturn("approle").when(properties).setProperty(VAULT_SECRET_BACKEND, "approle");
        doReturn("vault").when(properties).setProperty(VAULT_STORAGE_BEHAVIOUR, "vault");

        doReturn("5").when(properties).getProperty(VAULT_MAX_RETRIES);
        doReturn("2").when(properties).getProperty(VAULT_READ_TIMEOUT);
        doReturn("2").when(properties).getProperty(VAULT_OPEN_TIMEOUT);
        doReturn("1000").when(properties).getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS);

        clearInvocations(vaultClientProvider);

        vaultStoragePlugin.properties=properties;
        vaultStoragePlugin.lookup();

        verify(vaultClientProvider, times(2)).getVaultClient();
    }
}
