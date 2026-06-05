package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.json.Json;
import io.github.jopenlibs.vault.json.JsonObject;
import io.github.jopenlibs.vault.json.JsonValue;
import io.github.jopenlibs.vault.rest.Rest;
import io.github.jopenlibs.vault.rest.RestResponse;
import io.github.jopenlibs.vault.SslConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * KV v2: reads {@code <mount>/metadata/<path>} to obtain the secret-level {@code created_time} and
 * {@code updated_time}. The data read ({@code <mount>/data/<path>}) only exposes per-version metadata and
 * does not include {@code updated_time}.
 */
final class VaultKvMetadataReader {

    private static final Logger LOG = LoggerFactory.getLogger(VaultKvMetadataReader.class);

    static final class SecretTimestamps {
        final String createdTime;
        final String updatedTime;

        SecretTimestamps(String createdTime, String updatedTime) {
            this.createdTime = createdTime;
            this.updatedTime = updatedTime;
        }
    }

    private VaultKvMetadataReader() {
    }

    /**
     * Parses the JSON body of a successful {@code GET /v1/.../metadata/...} response.
     */
    static SecretTimestamps parseMetadataResponseBody(String body) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        try {
            JsonValue rootVal = Json.parse(body);
            if (!rootVal.isObject()) {
                return null;
            }
            JsonObject root = rootVal.asObject();
            JsonValue dataVal = root.get("data");
            if (dataVal == null || !dataVal.isObject()) {
                return null;
            }
            JsonObject data = dataVal.asObject();
            String created = data.getString("created_time", null);
            String updated = data.getString("updated_time", null);
            if (created == null && updated == null) {
                return null;
            }
            return new SecretTimestamps(created, updated);
        } catch (RuntimeException e) {
            LOG.debug("Failed to parse KV metadata JSON: {}", e.getMessage());
            return null;
        }
    }

    static void mergeInto(Map<String, String> dataReadMetadata, SecretTimestamps secretTimestamps) {
        if (dataReadMetadata == null || secretTimestamps == null) {
            return;
        }
        if (secretTimestamps.createdTime != null) {
            dataReadMetadata.put("created_time", secretTimestamps.createdTime);
        }
        if (secretTimestamps.updatedTime != null) {
            dataReadMetadata.put("updated_time", secretTimestamps.updatedTime);
        }
    }

    /**
     * Best-effort HTTP GET to the metadata path. Returns {@code null} on any failure (including 403).
     */
    static SecretTimestamps readSecretTimestamps(VaultConfig config, String metadataLogicalPath) {
        if (config == null || metadataLogicalPath == null || metadataLogicalPath.isEmpty()) {
            return null;
        }
        try {
            String address = config.getAddress();
            if (address == null || address.isEmpty()) {
                return null;
            }
            if (address.endsWith("/")) {
                address = address.substring(0, address.length() - 1);
            }
            String url = address + "/v1/" + metadataLogicalPath;

            // Reuse the shared HttpClient set on VaultConfig; falling back to a new Rest() would create
            // a fresh java.net.http.HttpClient on every call and leak native threads under bulk listing.
            HttpClient httpClient = config.getHttpClient();
            Rest rest = (httpClient != null) ? new Rest(httpClient) : new Rest();
            rest.url(url);
            String token = config.getToken();
            if (token != null && !token.isEmpty()) {
                rest.header("X-Vault-Token", token);
            }
            String namespace = config.getNameSpace();
            if (namespace != null && !namespace.isEmpty()) {
                rest.header("X-Vault-Namespace", namespace);
            }

            SslConfig sslConfig = config.getSslConfig();
            if (sslConfig != null) {
                rest.sslVerification(sslConfig.isVerify());
                if (sslConfig.getSslContext() != null) {
                    rest.sslContext(sslConfig.getSslContext());
                }
            }

            Integer openTimeout = config.getOpenTimeout();
            Integer readTimeout = config.getReadTimeout();
            if (openTimeout != null) {
                rest.connectTimeoutSeconds(openTimeout);
            }
            if (readTimeout != null) {
                rest.readTimeoutSeconds(readTimeout);
            }

            RestResponse response = rest.get();
            if (response.getStatus() != 200) {
                LOG.debug("KV metadata GET returned status {} for path {}", response.getStatus(), metadataLogicalPath);
                return null;
            }
            byte[] bodyBytes = response.getBody();
            if (bodyBytes == null || bodyBytes.length == 0) {
                return null;
            }
            return parseMetadataResponseBody(new String(bodyBytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            LOG.debug("KV metadata GET failed for path {}: {}", metadataLogicalPath, e.getMessage());
            return null;
        }
    }
}
