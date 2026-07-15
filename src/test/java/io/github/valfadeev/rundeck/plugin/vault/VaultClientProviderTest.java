package io.github.valfadeev.rundeck.plugin.vault;

import java.io.InputStream;
import java.util.Properties;

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
}
