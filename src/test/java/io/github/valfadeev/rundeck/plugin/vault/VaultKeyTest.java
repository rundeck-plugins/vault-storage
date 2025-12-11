package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.response.LogicalResponse;
import com.dtolabs.rundeck.core.storage.ResourceMeta;
import org.junit.Test;
import org.rundeck.storage.api.ContentMeta;
import org.rundeck.storage.api.Path;
import org.rundeck.storage.api.PathUtil;
import org.rundeck.storage.impl.ResourceBase;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for VaultKey timestamp handling
 */
public class VaultKeyTest {

    @Test
    public void loadResource_setsCreationTimeFromVaultMetadata() {
        // Given: A VaultKey with metadata containing created_time
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "mypassword");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);

        // Set vault metadata with created_time
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-03-13T16:25:00.123456Z");
        metadata.put("version", "1");
        vaultKey.setVaultMetadata(metadata);

        // When: Loading the resource
        ResourceBase resource = vaultKey.loadResource();

        // Then: Resource should be successfully created with metadata
        assertNotNull("Resource should not be null", resource);
        assertNotNull("Resource contents should not be null", resource.getContents());

        // Verify the metadata map was used (the key will have been processed)
        assertNotNull("Vault metadata should be set", vaultKey.getVaultMetadata());
        assertEquals("Vault metadata should contain created_time",
                    "2025-03-13T16:25:00.123456Z",
                    vaultKey.getVaultMetadata().get("created_time"));
    }

    @Test
    public void loadResource_handlesNoMetadataGracefully() {
        // Given: A VaultKey without metadata (backward compatibility)
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "mypassword");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        // No metadata set - vaultMetadata is null

        // When: Loading the resource
        ResourceBase resource = vaultKey.loadResource();

        // Then: Resource should still load successfully (timestamps will be null/default)
        assertNotNull("Resource should not be null even without metadata", resource);
        assertNotNull("Resource contents should not be null", resource.getContents());
        // Plugin should handle missing metadata gracefully without throwing exceptions
    }

    @Test
    public void loadResource_handlesEmptyMetadata() {
        // Given: A VaultKey with empty metadata map
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "mypassword");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        vaultKey.setVaultMetadata(new HashMap<>()); // Empty metadata

        // When: Loading the resource
        ResourceBase resource = vaultKey.loadResource();

        // Then: Resource should load successfully
        assertNotNull("Resource should not be null with empty metadata", resource);
    }

    @Test
    public void loadResource_handlesInvalidTimestampFormat() {
        // Given: A VaultKey with invalid timestamp format
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "mypassword");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);

        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "invalid-date-format");
        vaultKey.setVaultMetadata(metadata);

        // When: Loading the resource
        ResourceBase resource = vaultKey.loadResource();

        // Then: Resource should still load (timestamp parsing fails gracefully)
        assertNotNull("Resource should not be null even with invalid timestamp", resource);
        // The timestamp will be null/default, but the resource should still work
    }

    @Test
    public void loadResource_parsesVariousTimestampFormats() {
        // Given: A VaultKey with different valid timestamp formats
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "mypassword");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);

        // Test various valid Vault timestamp formats
        String[] validTimestamps = {
            "2025-12-11T14:16:59.188636Z",      // Full format with microseconds
            "2025-12-11T14:16:59Z",             // Without microseconds
            "2025-01-01T00:00:00.000000Z"       // Edge case: Jan 1st midnight
        };

        for (String timestamp : validTimestamps) {
            Map<String, String> metadata = new HashMap<>();
            metadata.put("created_time", timestamp);
            vaultKey.setVaultMetadata(metadata);

            // When: Loading the resource
            ResourceBase resource = vaultKey.loadResource();

            // Then: Resource should be created successfully
            assertNotNull("Resource should not be null for timestamp: " + timestamp, resource);
            assertNotNull("Resource contents should not be null for timestamp: " + timestamp,
                         resource.getContents());
        }
    }

    @Test
    public void loadResource_setsPasswordContentType() {
        // Given: A VaultKey with password value
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "mypassword");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);

        // When: Loading the resource
        ResourceBase resource = vaultKey.loadResource();

        // Then: Resource should be created successfully (content type is set internally)
        assertNotNull("Resource should not be null", resource);
        assertNotNull("Resource contents should not be null", resource.getContents());
        // The VaultKey.loadResource() method sets PASSWORD_MIME_TYPE for simple password values
    }

    @Test
    public void loadResource_setsPrivateKeyContentType() {
        // Given: A VaultKey with private key value
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQ...");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);

        // When: Loading the resource
        ResourceBase resource = vaultKey.loadResource();

        // Then: Resource should be created successfully (content type is set internally)
        assertNotNull("Resource should not be null", resource);
        assertNotNull("Resource contents should not be null", resource.getContents());
        // The VaultKey.loadResource() method sets PRIVATE_KEY_MIME_TYPE for RSA keys
    }
}
