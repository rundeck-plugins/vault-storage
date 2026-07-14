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

import java.net.URLEncoder;
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

    /**
     * Fallback {@link HttpClient} used only when the {@link VaultConfig} does not carry a shared client.
     * java.net.http.HttpClient is thread-safe and meant to be shared; keeping a single static instance
     * avoids spawning a fresh client (and its native selector/worker threads) on every metadata call
     * during bulk listing.
     */
    private static volatile HttpClient fallbackHttpClient;

    private VaultKvMetadataReader() {
    }

    private static HttpClient getFallbackHttpClient(SslConfig sslConfig) {
        HttpClient client = fallbackHttpClient;
        if (client == null) {
            synchronized (VaultKvMetadataReader.class) {
                client = fallbackHttpClient;
                if (client == null) {
                    HttpClient.Builder builder = HttpClient.newBuilder();
                    if (sslConfig != null && sslConfig.getSslContext() != null) {
                        builder.sslContext(sslConfig.getSslContext());
                    }
                    client = builder.build();
                    fallbackHttpClient = client;
                    LOG.debug("[vault] created fallback shared HttpClient for KV metadata calls");
                }
            }
        }
        return client;
    }

    /**
     * URL-encodes each path segment while preserving the {@code /} separators, so logical paths containing
     * characters such as spaces, {@code #}, {@code ?} or {@code %} produce valid Vault requests.
     */
    static String encodeLogicalPath(String logicalPath) {
        String[] segments = logicalPath.split("/", -1);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < segments.length; i++) {
            if (i > 0) {
                sb.append('/');
            }
            // URLEncoder targets application/x-www-form-urlencoded (encodes space as '+'); path
            // segments need percent-encoding, so normalize '+' back to '%20'.
            sb.append(URLEncoder.encode(segments[i], StandardCharsets.UTF_8).replace("+", "%20"));
        }
        return sb.toString();
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
            String url = address + "/v1/" + encodeLogicalPath(metadataLogicalPath);

            SslConfig sslConfig = config.getSslConfig();

            // Reuse the shared HttpClient set on VaultConfig; fall back to a single static shared client
            // rather than creating a fresh java.net.http.HttpClient per call, which would leak native
            // threads under bulk listing.
            HttpClient httpClient = config.getHttpClient();
            if (httpClient == null) {
                httpClient = getFallbackHttpClient(sslConfig);
            }
            Rest rest = new Rest(httpClient);
            rest.url(url);
            String token = config.getToken();
            if (token != null && !token.isEmpty()) {
                rest.header("X-Vault-Token", token);
            }
            String namespace = config.getNameSpace();
            if (namespace != null && !namespace.isEmpty()) {
                rest.header("X-Vault-Namespace", namespace);
            }

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
