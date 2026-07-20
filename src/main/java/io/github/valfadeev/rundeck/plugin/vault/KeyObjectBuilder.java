package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.DataMetadata;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.rundeck.storage.api.Path;
import org.rundeck.storage.api.PathUtil;

import java.util.HashMap;
import java.util.Map;

public class KeyObjectBuilder {

    Path path;
    Logical vault;
    String vaultPrefix;
    String vaultSecretBackend;
    boolean useVaultMetadataTimestamps;
    int engineVersion = 1;
    VaultConfig vaultConfig;

    static KeyObjectBuilder builder() {
        return new KeyObjectBuilder();
    }

    KeyObjectBuilder path(Path path) {
        this.path = path;
        return this;
    }

    KeyObjectBuilder vault(Logical vault) {
        this.vault = vault;
        return this;
    }

    KeyObjectBuilder vaultPrefix(String vaultPrefix) {
        this.vaultPrefix = vaultPrefix;
        return this;
    }

    KeyObjectBuilder vaultSecretBackend(String vaultSecretBackend) {
        this.vaultSecretBackend = vaultSecretBackend;
        return this;
    }

    KeyObjectBuilder useVaultMetadataTimestamps(boolean useVaultMetadataTimestamps) {
        this.useVaultMetadataTimestamps = useVaultMetadataTimestamps;
        return this;
    }

    KeyObjectBuilder engineVersion(int engineVersion) {
        this.engineVersion = engineVersion;
        return this;
    }

    KeyObjectBuilder vaultConfig(VaultConfig vaultConfig) {
        this.vaultConfig = vaultConfig;
        return this;
    }

    /**
     * When KV v2 data read reports version &gt; 1, optionally load secret-level timestamps from the metadata endpoint
     * and merge them into the map used by {@link VaultKey#loadResource()}.
     */
    private void mergeKv2SecretTimestamps(Path secretPath, Map<String, String> dataReadMetadata, DataMetadata dataMetadata) {
        if (!useVaultMetadataTimestamps || engineVersion != 2 || vaultConfig == null) {
            return;
        }
        if (dataReadMetadata == null || dataMetadata == null || dataMetadata.isEmpty()) {
            return;
        }
        Long version = dataMetadata.getVersion();
        if (version == null || version <= 1) {
            return;
        }
        String logicalMetadataPath = VaultStoragePlugin.getVaultMetadataPath(
                secretPath.getPath(),
                vaultSecretBackend,
                vaultPrefix);
        VaultKvMetadataReader.SecretTimestamps secretTimestamps =
                VaultKvMetadataReader.readSecretTimestamps(vaultConfig, logicalMetadataPath);
        VaultKvMetadataReader.mergeInto(dataReadMetadata, secretTimestamps);
    }

    KeyObject build() {
        LogicalResponse response;
        KeyObject object;
        try {
            response = vault.read(VaultStoragePlugin.getVaultPath(path.getPath(), vaultSecretBackend, vaultPrefix));
            String data = response.getData().get(VaultStoragePlugin.VAULT_STORAGE_KEY);

            Map<String, String> metadata = null;
            DataMetadata dataMetadata = response.getDataMetadata();
            if (dataMetadata != null && !dataMetadata.isEmpty()) {
                metadata = new HashMap<>(dataMetadata.getMetadataMap());
            }

            if (data != null) {
                object = new RundeckKey(response, path);
            } else {
                object = new VaultKey(response, path);
                object.setVaultMetadata(metadata);
                if (metadata != null) {
                    mergeKv2SecretTimestamps(path, metadata, dataMetadata);
                }
            }

            if (response.getRestResponse().getStatus() != 200) {
                object.error = true;
            }

        } catch (VaultException e) {
            object = new RundeckKey(path);
            object.setErrorMessage(e.getMessage());
            object.setError(true);
        }

        if (object.isError()) {
            KeyObject parentObject = getVaultParentObject(path);

            if (parentObject != null) {
                object = new VaultKey(path, parentObject);
                Path parentPath = PathUtil.parentPath(path);
                String key = PathUtil.removePrefix(parentPath.toString(), path.toString());

                object.setError(false);
                object.setErrorMessage(null);
                object.setMultiplesKeys(true);

                if (parentObject.getKeys().containsKey(key)) {
                    object.getKeys().put(key, parentObject.getKeys().get(key));
                }
                if (parentObject.getVaultMetadata() != null) {
                    object.setVaultMetadata(new HashMap<>(parentObject.getVaultMetadata()));
                }
            }
        }

        return object;
    }

    public KeyObject getVaultParentObject(Path path) {
        KeyObject parentObject = null;
        LogicalResponse response;

        Path parentPath = PathUtil.parentPath(path);
        try {
            response = vault.read(VaultStoragePlugin.getVaultPath(parentPath.getPath(), vaultSecretBackend, vaultPrefix));

            if (response.getRestResponse().getStatus() != 200) {
                return null;
            }

            parentObject = new VaultKey(response, parentPath);

            DataMetadata dataMetadata = response.getDataMetadata();
            if (dataMetadata != null && !dataMetadata.isEmpty()) {
                Map<String, String> metadata = new HashMap<>(dataMetadata.getMetadataMap());
                parentObject.setVaultMetadata(metadata);
                mergeKv2SecretTimestamps(parentPath, metadata, dataMetadata);
            }
        } catch (VaultException e) {
            // Parent object doesn't exist, return null - this is expected in some cases
        }

        return parentObject;
    }
}
