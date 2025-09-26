package io.github.valfadeev.rundeck.plugin.vault;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;

import io.github.jopenlibs.vault.SslConfig;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultConfig;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Auth;
import com.dtolabs.rundeck.core.plugins.configuration.ConfigurationException;

import static io.github.valfadeev.rundeck.plugin.vault.ConfigOptions.*;
import static io.github.valfadeev.rundeck.plugin.vault.SupportedAuthBackends.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

class VaultClientProvider {
    private static final Logger LOG = LoggerFactory.getLogger(VaultClientProvider.class);

    private Properties configuration;

    VaultClientProvider(Properties configuration) {
        this.configuration = configuration;
    }

    Vault getVaultClient() throws ConfigurationException {
        LOG.error("[vault] getVaultClient(): start, address='{}'", configuration.getProperty(VAULT_ADDRESS));
        final Integer vaultMaxRetries = Integer.parseInt(configuration.getProperty(VAULT_MAX_RETRIES));
        final Integer vaultRetryIntervalMilliseconds = Integer.parseInt(configuration.getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS));
        final Integer vaultEngineVersion = Integer.parseInt(configuration.getProperty(VAULT_ENGINE_VERSION));

        VaultConfig vaultConfig = getVaultConfig();

        try {
            String authToken = getVaultAuthToken();
            LOG.error("[vault] got auth token? {}", (authToken != null && !authToken.isEmpty()));
            vaultConfig.token(authToken).build();
            LOG.error("[vault] building Vault client with engineVersion={} retries={} interval={}ms",
                    vaultEngineVersion, vaultMaxRetries, vaultRetryIntervalMilliseconds);
            return Vault.create(vaultConfig, vaultEngineVersion).withRetries(vaultMaxRetries,
                    vaultRetryIntervalMilliseconds);

        } catch (VaultException e) {
            LOG.error("[vault] getVaultClient(): VaultException: {}", e.getMessage(), e);
            throw new ConfigurationException(String.format("Encountered error while "
                    + "building Vault configuration: %s", e.getMessage()));
        }
    }

    protected VaultConfig getVaultConfig() throws ConfigurationException {
        final String vaultAddress = configuration.getProperty(VAULT_ADDRESS);
        final String nameSpace = configuration.getProperty(VAULT_NAMESPACE);
        final Integer vaultOpenTimeout = Integer.parseInt(configuration.getProperty(VAULT_OPEN_TIMEOUT));
        final Integer vaultReadTimeout = Integer.parseInt(configuration.getProperty(VAULT_READ_TIMEOUT));

        final SslConfig sslConfig = getSslConfig();

        VaultConfig vaultConfig = new VaultConfig();
        vaultConfig.address(vaultAddress)
                .openTimeout(vaultOpenTimeout)
                .readTimeout(vaultReadTimeout)
                .sslConfig(sslConfig);

        if(nameSpace != null){
            try {
                vaultConfig.nameSpace(nameSpace);
            } catch (VaultException e) {
                LOG.error("[vault] error building namespace configuration: {}", e.getMessage(), e);
                throw new ConfigurationException(
                        String.format("Encountered error while building namespace configuration: %s", e.getMessage()));
            }
        }

        LOG.error("[vault] built VaultConfig for address='{}', namespace='{}'", vaultAddress, nameSpace);
        return vaultConfig;
    }

    private SslConfig getSslConfig() throws ConfigurationException {
        SslConfig sslConfig = new SslConfig();

        final Boolean vaultVerifySsl = Boolean.parseBoolean(configuration.getProperty(VAULT_VERIFY_SSL));
        sslConfig.verify(vaultVerifySsl);
        LOG.error("[vault] SSL verify={}", vaultVerifySsl);

        final String vaultTrustStoreFile = configuration.getProperty(VAULT_TRUST_STORE_FILE);
        if (vaultTrustStoreFile != null) {
            try {
                LOG.error("[vault] using trustStoreFile={}", vaultTrustStoreFile);
                File trustFile = new File(vaultTrustStoreFile);
                LOG.error("[vault] trustStoreFile exists={}, readable={}, size={}",
                        trustFile.exists(), trustFile.canRead(), trustFile.length());
                sslConfig.trustStoreFile(trustFile);
                LOG.error("[vault] trustStoreFile configuration applied successfully");
            } catch (VaultException e) {
                LOG.error("[vault] error setting trustStoreFile: {}", e.getMessage(), e);
                throw new ConfigurationException(String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
            }
        } else {
            final String vaultPemFile = configuration.getProperty(VAULT_PEM_FILE);
            if (vaultPemFile != null) {
                try {
                    LOG.error("[vault] configured pemFile: {}", vaultPemFile);
                    File pemFile = new File(vaultPemFile);
                    LOG.error("[vault] pemFile exists={}, readable={}, size={}",
                            pemFile.exists(), pemFile.canRead(), pemFile.length());
                    sslConfig.pemFile(pemFile);
                    LOG.error("[vault] pemFile configuration applied successfully");
                }
                catch (VaultException e) {
                    LOG.error("[vault] error setting pemFile: {}", e.getMessage(), e);
                    throw new ConfigurationException(
                            String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
                }
            } else {
                LOG.error("[vault] no trustStoreFile or pemFile configured");
            }
        }

        final String vaultAuthBackend = configuration.getProperty(VAULT_AUTH_BACKEND);
        LOG.error("[vault] authBackend={}", vaultAuthBackend);

        if (vaultAuthBackend != null && vaultAuthBackend.equals(CERT)) {
            LOG.error("[vault] configuring client certificate for CERT auth");

            final String vaultKeyStoreFile = configuration.getProperty(VAULT_KEY_STORE_FILE);
            final String vaultKeyStoreFilePassword = configuration.getProperty(VAULT_KEY_STORE_FILE_PASSWORD);

            LOG.error("[vault] keyStoreFile={}, keyStoreFilePassword={}",
                    vaultKeyStoreFile, (vaultKeyStoreFilePassword != null ? "***set***" : "null"));

            if (vaultKeyStoreFile != null && vaultKeyStoreFilePassword != null) {
                try {
                    LOG.error("[vault] using keyStoreFile={}", vaultKeyStoreFile);
                    File keyFile = new File(vaultKeyStoreFile);
                    LOG.error("[vault] keyStoreFile exists={}, readable={}, size={}",
                            keyFile.exists(), keyFile.canRead(), keyFile.length());
                    sslConfig.keyStoreFile(keyFile, vaultKeyStoreFilePassword);
                    LOG.error("[vault] keyStore configuration applied successfully");
                } catch (VaultException e) {
                    LOG.error("[vault] error setting keyStoreFile: {}", e.getMessage(), e);
                    throw new ConfigurationException(String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
                }
            } else {
                final String vaultClientPemFile = configuration.getProperty(VAULT_CLIENT_PEM_FILE);
                final String vaultClientKeyPemFile = configuration.getProperty(VAULT_CLIENT_KEY_PEM_FILE);

                LOG.error("[vault] clientPemFile={}, clientKeyPemFile={}", vaultClientPemFile, vaultClientKeyPemFile);

                if (vaultClientPemFile != null && vaultClientKeyPemFile != null) {
                    try {
                        LOG.error("[vault] using clientPemFile={} clientKeyPemFile={}",
                                vaultClientPemFile, vaultClientKeyPemFile);

                        File clientPemFile = new File(vaultClientPemFile);
                        File clientKeyFile = new File(vaultClientKeyPemFile);

                        LOG.error("[vault] clientPemFile exists={}, readable={}, size={}",
                                clientPemFile.exists(), clientPemFile.canRead(), clientPemFile.length());
                        LOG.error("[vault] clientKeyPemFile exists={}, readable={}, size={}",
                                clientKeyFile.exists(), clientKeyFile.canRead(), clientKeyFile.length());

                        // Create custom SSL context instead of relying on SslConfig
                        SSLContext customSslContext = createCustomSSLContext(clientPemFile, clientKeyFile, vaultVerifySsl);
                        LOG.error("[vault] created custom SSL context with client certificate");

                        // Use reflection to set the SSL context since sslContext() method is private
                        try {
                            java.lang.reflect.Field sslContextField = SslConfig.class.getDeclaredField("sslContext");
                            sslContextField.setAccessible(true);
                            sslContextField.set(sslConfig, customSslContext);
                            LOG.error("[vault] set custom SSL context via reflection");
                        } catch (Exception e) {
                            LOG.error("[vault] failed to set SSL context via reflection: {}", e.getMessage());
                            throw new ConfigurationException("Failed to configure SSL context: " + e.getMessage());
                        }

                    } catch (Exception e) {
                        LOG.error("[vault] error creating custom SSL context: {}", e.getMessage(), e);
                        throw new ConfigurationException(String.format("Error configuring client certificate: %s", e.getMessage()));
                    }
                } else {
                    LOG.error("[vault] CERT auth backend selected but client PEM files not configured!");
                    throw new ConfigurationException("CERT authentication backend requires clientPemFile and clientKeyPemFile configuration");
                }
            }
        } else {
            LOG.error("[vault] not configuring client certificate (authBackend is not CERT or is null)");
        }

        try {
            LOG.error("[vault] building SslConfig...");
            sslConfig.build();
            LOG.error("[vault] built SslConfig successfully");
            LOG.error("[vault] Final SSL config - verify: {}", sslConfig.isVerify());
        } catch (VaultException e) {
            LOG.error("[vault] VaultException while building SslConfig: {}", e.getMessage(), e);
            throw new ConfigurationException(String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
        } catch (Exception e) {
            LOG.error("[vault] Unexpected exception while building SslConfig: {}", e.getMessage(), e);
            throw new ConfigurationException(String.format("Unexpected error while building SSL configuration: %s", e.getMessage()));
        }

        return sslConfig;
    }

    private SSLContext createCustomSSLContext(File clientCertFile, File clientKeyFile, boolean verifySsl)
            throws Exception {

        // Load client certificate
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        java.security.cert.X509Certificate clientCert;
        try (FileInputStream certStream = new FileInputStream(clientCertFile)) {
            clientCert = (java.security.cert.X509Certificate) cf.generateCertificate(certStream);
        }

        // Load private key
        PrivateKey privateKey;
        try (FileInputStream keyStream = new FileInputStream(clientKeyFile)) {
            byte[] keyBytes = keyStream.readAllBytes();
            String keyString = new String(keyBytes, StandardCharsets.UTF_8)
                    .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyData = Base64.getDecoder().decode(keyString);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            privateKey = keyFactory.generatePrivate(keySpec);
        }

        // Create keystore with client certificate
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", privateKey, "".toCharArray(), new java.security.cert.Certificate[]{clientCert});

        // Create key manager
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "".toCharArray());

        // Create trust manager
        TrustManager[] trustManagers;
        if (verifySsl) {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            trustManagers = tmf.getTrustManagers();
        } else {
            // Create trust-all manager for testing
            trustManagers = new TrustManager[]{
                    new javax.net.ssl.X509TrustManager() {
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
                    }
            };
        }

        // Create SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), trustManagers, new java.security.SecureRandom());

        return sslContext;
    }

    private String getVaultAuthToken() throws ConfigurationException, VaultException {
        final String vaultAuthBackend = configuration.getProperty(VAULT_AUTH_BACKEND);
        final String vaultAuthNameSpace = configuration.getProperty(VAULT_AUTH_NAMESPACE);

        LOG.error("[vault] getVaultAuthToken(): backend='{}', authNamespace='{}'",
                vaultAuthBackend, vaultAuthNameSpace);

        final String authToken;
        final String msg = "Must specify %s when auth backend is %s";

        if (vaultAuthBackend.equals(TOKEN)) {
            LOG.error("[vault] auth=TOKEN");
            authToken = configuration.getProperty(VAULT_TOKEN);
            if (authToken == null) {
                LOG.error("[vault] missing token for TOKEN backend");
                throw new ConfigurationException(String.format(msg, VAULT_TOKEN, vaultAuthBackend));
            }
            return authToken;
        }

        final VaultConfig vaultAuthConfig = getVaultConfig();

        if(vaultAuthNameSpace!=null && !vaultAuthNameSpace.isEmpty()){
            vaultAuthConfig.nameSpace(vaultAuthNameSpace);
        }
        try {
            vaultAuthConfig.build();
        } catch (VaultException e) {
            throw new ConfigurationException(
                    String.format("Encountered error while building Vault auth configuration: %s", e.getMessage())
            );
        }
        final Auth vaultAuth = Vault.create(vaultAuthConfig).auth();

        switch (vaultAuthBackend) {

            case APPROLE:
                LOG.error("[vault] auth=APPROLE");
                final String vaultApproleId = configuration.getProperty(VAULT_APPROLE_ID);
                final String vaultApproleSecretId = configuration.getProperty(VAULT_APPROLE_SECRET_ID);
                final String vaultApproleAuthMount = configuration.getProperty(VAULT_APPROLE_AUTH_MOUNT);

                if (vaultApproleId == null || vaultApproleSecretId == null) {
                    LOG.error("[vault] missing AppRole id/secret");
                    throw new ConfigurationException(
                            String.format(msg,
                                    String.join(", ",
                                            new String[]{VAULT_APPROLE_ID, VAULT_APPROLE_SECRET_ID}),
                                    vaultAuthBackend));
                }

                try {
                    authToken = vaultAuth.loginByAppRole(
                            vaultApproleAuthMount,
                            vaultApproleId,
                            vaultApproleSecretId).getAuthClientToken();
                    LOG.error("[vault] AppRole login success? {}", (authToken != null));
                } catch (VaultException e) {
                    LOG.error("[vault] AppRole login failed: {}", e.getMessage(), e);
                    throw new ConfigurationException(String.format("Encountered error while authenticating with %s: %s",
                            vaultAuthBackend, e.getLocalizedMessage()));
                }
                break;

            case GITHUB:
                LOG.error("[vault] auth=GITHUB");
                final String vaultGithubToken = configuration.getProperty(VAULT_GITHUB_TOKEN);
                if (vaultGithubToken == null) {
                    LOG.error("[vault] missing github token");
                    throw new ConfigurationException(
                            String.format(msg, VAULT_GITHUB_TOKEN, vaultAuthBackend));
                }

                try {
                    authToken = vaultAuth.loginByGithub(vaultGithubToken).getAuthClientToken();
                    LOG.error("[vault] GitHub login success? {}", (authToken != null));
                } catch (VaultException e) {
                    LOG.error("[vault] GitHub login failed: {}", e.getMessage(), e);
                    throw new ConfigurationException(String.format("Encountered error while authenticating with %s",
                            vaultAuthBackend));
                }
                break;

            case USERPASS:
                LOG.error("[vault] auth=USERPASS");
                final String vaultUserpassAuthMount = configuration.getProperty(VAULT_USERPASS_AUTH_MOUNT);
                final String vaultUsername = configuration.getProperty(VAULT_USERNAME);
                final String vaultPassword = configuration.getProperty(VAULT_PASSWORD);
                if (vaultUsername == null || vaultPassword == null) {
                    LOG.error("[vault] missing user/password");
                    throw new ConfigurationException(
                            String.format(msg,
                                    String.join(", ",
                                            new String[]{VAULT_USERNAME, VAULT_PASSWORD}),
                                    vaultAuthBackend));
                }

                try {
                    authToken = vaultAuth.loginByUserPass(vaultUsername, vaultPassword, vaultUserpassAuthMount)
                            .getAuthClientToken();
                    LOG.error("[vault] UserPass login success? {}", (authToken != null));
                } catch (VaultException e) {
                    LOG.error("[vault] UserPass login failed: {}", e.getMessage(), e);
                    throw new ConfigurationException(String.format("Encountered error while authenticating with %s",
                            vaultAuthBackend));
                }
                break;

            case CERT:
                String certMount = null;
                try {
                    // Get the certificate mount path (defaults to "cert" if not specified)
                    certMount = configuration.getProperty(VAULT_CERT_AUTH_MOUNT, "cert");

                    LOG.error("[vault] attempting cert auth with mount path: {}", certMount);

                    authToken = vaultAuth.loginByCert(certMount).getAuthClientToken();

                    LOG.error("[vault] cert auth successful, got token");

                } catch (VaultException e) {
                    LOG.error("[vault] Cert login failed: {}", e.getMessage());
                    throw new ConfigurationException(
                            String.format("Encountered error while authenticating with %s at mount '%s': %s",
                                    vaultAuthBackend, certMount, e.getMessage()));
                }
                break;

            default:
                LOG.error("[vault] unsupported auth backend='{}'", vaultAuthBackend);
                throw new ConfigurationException(String.format("Unsupported auth backend: %s", vaultAuthBackend));
        }

        return authToken;
    }
}
