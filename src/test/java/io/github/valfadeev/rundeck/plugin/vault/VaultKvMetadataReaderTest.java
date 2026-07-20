package io.github.valfadeev.rundeck.plugin.vault;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class VaultKvMetadataReaderTest {

    @Test
    public void parseMetadataResponseBody_extractsCreatedAndUpdated() {
        String json = "{\"data\":{\"created_time\":\"2020-01-02T00:00:00Z\",\"updated_time\":\"2020-03-04T12:00:00Z\",\"current_version\":3}}";
        VaultKvMetadataReader.SecretTimestamps ts = VaultKvMetadataReader.parseMetadataResponseBody(json);
        assertNotNull(ts);
        assertEquals("2020-01-02T00:00:00Z", ts.createdTime);
        assertEquals("2020-03-04T12:00:00Z", ts.updatedTime);
    }

    @Test
    public void parseMetadataResponseBody_invalid_returnsNull() {
        assertNull(VaultKvMetadataReader.parseMetadataResponseBody(""));
        assertNull(VaultKvMetadataReader.parseMetadataResponseBody("not json"));
        assertNull(VaultKvMetadataReader.parseMetadataResponseBody("{\"list\":[]}"));
    }

    @Test
    public void mergeInto_overwritesCreatedAndAddsUpdated() {
        Map<String, String> meta = new HashMap<>();
        meta.put("created_time", "wrong");
        meta.put("version", "3");
        VaultKvMetadataReader.mergeInto(meta, new VaultKvMetadataReader.SecretTimestamps("orig", "mod"));
        assertEquals("orig", meta.get("created_time"));
        assertEquals("mod", meta.get("updated_time"));
        assertEquals("3", meta.get("version"));
    }

    @Test
    public void getVaultMetadataPath_withAndWithoutPrefix() {
        assertEquals("secret/metadata/prefix/a/b", VaultStoragePlugin.getVaultMetadataPath("a/b", "secret", "prefix"));
        assertEquals("secret/metadata/a/b", VaultStoragePlugin.getVaultMetadataPath("a/b", "secret", null));
        assertEquals("secret/metadata/a/b", VaultStoragePlugin.getVaultMetadataPath("a/b", "secret", ""));
    }

    @Test
    public void encodeLogicalPath_leavesPlainSegmentsUnchanged() {
        assertEquals("secret/metadata/a/b", VaultKvMetadataReader.encodeLogicalPath("secret/metadata/a/b"));
    }

    @Test
    public void encodeLogicalPath_preservesSeparatorsAndEncodesSegments() {
        // '/' separators are preserved; spaces and reserved characters are percent-encoded per segment.
        assertEquals("secret/metadata/my%20key/a%23b",
                VaultKvMetadataReader.encodeLogicalPath("secret/metadata/my key/a#b"));
        assertEquals("secret/metadata/q%3Fx/50%25",
                VaultKvMetadataReader.encodeLogicalPath("secret/metadata/q?x/50%"));
    }
}
