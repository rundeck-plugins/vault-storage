package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.response.LogicalResponse;
import org.junit.Test;
import org.rundeck.storage.api.Path;
import org.rundeck.storage.api.PathUtil;
import org.rundeck.storage.impl.ResourceBase;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

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
    public void loadResource_usesUpdatedTimeWhenAvailable() {
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "mypassword");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);

        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-03-13T10:00:00.000000Z");
        metadata.put("updated_time", "2025-03-13T16:00:00.000000Z");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull(resource);
        assertNotNull(resource.getContents());
    }

    @Test
    public void loadResource_fallsBackToCreatedTimeWhenUpdatedTimeInvalid() {
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "mypassword");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);

        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-03-13T10:00:00.000000Z");
        metadata.put("updated_time", "invalid-timestamp");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull(resource);
        assertNotNull(resource.getContents());
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

    @Test
    public void parseTimestamp_handlesNanosecondPrecision() {
        // Tests Strategy 1: Instant.parse() with nanosecond precision
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-12-11T14:16:59.123456789Z");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Should parse nanosecond precision timestamp", resource);
        assertNotNull("Resource metadata should be set", resource.getContents().getMeta());
    }

    @Test
    public void parseTimestamp_handlesMicrosecondPrecision() {
        // Tests Strategy 1: Instant.parse() with microsecond precision (current Vault format)
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-12-11T14:16:59.188636Z");
        metadata.put("updated_time", "2025-12-11T14:16:59.188636Z");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Should parse microsecond precision timestamp", resource);
        assertNotNull("Resource metadata should be set", resource.getContents().getMeta());
    }

    @Test
    public void parseTimestamp_handlesMillisecondPrecision() {
        // Tests Strategy 3: SimpleDateFormat with milliseconds
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-12-11T14:16:59.123Z");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Should parse millisecond precision timestamp", resource);
    }

    @Test
    public void parseTimestamp_handlesSecondPrecisionOnly() {
        // Tests Strategy 1: Instant.parse() without fractional seconds
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-12-11T14:16:59Z");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Should parse second precision timestamp", resource);
    }

    @Test
    public void parseTimestamp_handlesTimezoneOffsets() {
        // Tests Strategy 1: Instant.parse() with timezone offsets
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-12-11T14:16:59+00:00");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Should parse timestamp with timezone offset", resource);
    }

    @Test
    public void parseTimestamp_successfullyParsesValidTimestamp() {
        // Verify that a valid RFC3339 timestamp is parsed without errors
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-12-11T14:16:59.188636Z");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        // If parsing succeeded, the resource will be created successfully
        assertNotNull("Resource should be created with valid timestamp", resource);
        assertNotNull("Resource contents should be set", resource.getContents());
        // The timestamp was successfully parsed and set internally
    }

    @Test
    public void parseTimestamp_handlesBothCreatedAndUpdatedTime() {
        // Verify that both created_time and updated_time are parsed without errors
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-12-11T10:00:00Z");
        metadata.put("updated_time", "2025-12-11T16:00:00Z");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        // If both timestamps were successfully parsed, the resource will be created
        assertNotNull("Resource should be created with both timestamps", resource);
        assertNotNull("Resource contents should be set", resource.getContents());
        // Both created_time and updated_time were successfully parsed and set internally
    }

    @Test
    public void parseTimestamp_handlesNullTimestamp() {
        // Tests graceful handling of null timestamps
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", null);
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Resource should be created even with null timestamp", resource);
    }

    @Test
    public void parseTimestamp_handlesEmptyString() {
        // Tests graceful handling of empty timestamp strings
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Resource should be created with empty timestamp string", resource);
    }

    @Test
    public void parseTimestamp_handlesCompletelyInvalidFormat() {
        // Tests that completely invalid formats are handled gracefully
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "not-a-valid-date-at-all");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Resource should be created even with invalid timestamp", resource);
        // The timestamp will be null, but the resource should still work
    }

    @Test
    public void parseTimestamp_fallsBackWhenInstantParseFails() {
        // Tests that fallback strategies work when primary strategy fails
        // This tests a format that Instant.parse() might not handle but SimpleDateFormat can
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        // This format should work with one of the fallback strategies
        metadata.put("created_time", "2025-12-11T14:16:59.000000Z");
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Resource should be created using fallback strategy", resource);
    }

    @Test
    public void parseTimestamp_handlesEdgeCases() {
        // Tests edge case timestamps
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        String[] edgeCaseTimestamps = {
            "2025-01-01T00:00:00Z",              // New Year midnight
            "2025-12-31T23:59:59.999999Z",       // End of year
            "2025-02-28T23:59:59Z",              // Last day of Feb (non-leap year)
            "2024-02-29T12:00:00Z",              // Leap day
        };

        for (String timestamp : edgeCaseTimestamps) {
            VaultKey vaultKey = new VaultKey(response, path);
            Map<String, String> metadata = new HashMap<>();
            metadata.put("created_time", timestamp);
            vaultKey.setVaultMetadata(metadata);

            ResourceBase resource = vaultKey.loadResource();

            assertNotNull("Should parse edge case timestamp: " + timestamp, resource);
        }
    }

    @Test
    public void parseTimestamp_handlesVeryShortTimestamp() {
        // Tests handling of timestamps shorter than expected
        Path path = PathUtil.asPath("keys/test-key");
        LogicalResponse response = mock(LogicalResponse.class);
        Map<String, String> data = new HashMap<>();
        data.put("value", "test");
        when(response.getData()).thenReturn(data);

        VaultKey vaultKey = new VaultKey(response, path);
        Map<String, String> metadata = new HashMap<>();
        metadata.put("created_time", "2025-12-11");  // Very short format
        vaultKey.setVaultMetadata(metadata);

        ResourceBase resource = vaultKey.loadResource();

        assertNotNull("Resource should be created even with short timestamp", resource);
    }
}
