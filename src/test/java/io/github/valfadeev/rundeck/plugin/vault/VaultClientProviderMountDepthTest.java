package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.VaultConfig;
import org.junit.Test;

import java.util.Properties;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * For KV v2 the driver inserts "data"/"metadata" after the mount path, and has to be told how many
 * segments the mount has when it is more than one.
 */
public class VaultClientProviderMountDepthTest {

    private static VaultConfig configFor(String secretBackend) throws Exception {
        Properties configuration = new Properties();
        configuration.load(VaultClientProviderMountDepthTest.class
                .getResourceAsStream("rundeck-config.properties"));
        if (secretBackend != null) {
            configuration.setProperty("secretBackend", secretBackend);
        }
        return new VaultClientProvider(configuration).getVaultConfig();
    }

    @Test
    public void singleSegmentMountKeepsTheDriverDefault() throws Exception {
        assertThat(configFor("secret").getPrefixPathDepth(), is(1));
    }

    @Test
    public void unsetMountKeepsTheDriverDefault() throws Exception {
        assertThat(configFor(null).getPrefixPathDepth(), is(1));
    }

    @Test
    public void nestedMountSetsThePrefixPathDepth() throws Exception {
        assertThat(configFor("team/kv").getPrefixPathDepth(), is(2));
    }

    @Test
    public void surroundingSlashesAreNotCountedAsSegments() throws Exception {
        assertThat(configFor("/team/kv/").getPrefixPathDepth(), is(2));
    }
}
