package io.github.valfadeev.rundeck.plugin.vault;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
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

class VaultClientProvider {
    private static final Logger LOG = LoggerFactory.getLogger(VaultClientProvider.class);
    private final Properties configuration;

    VaultClientProvider(Properties configuration) {
        this.configuration = configuration;
    }

    Vault getVaultClient() throws ConfigurationException {
        LOG.error("[vault] getVaultClient(): start, address='{}'", configuration.getProperty(VAULT_ADDRESS));
        final int vaultMaxRetries = Integer.parseInt(configuration.getProperty(VAULT_MAX_RETRIES));
        final int vaultRetryIntervalMilliseconds = Integer.parseInt(configuration.getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS));
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

        final String vaultTrustStoreFile = configuration.getProperty(VAULT_TRUST_STORE_FILE);
        final String vaultTrustStoreFilePassword = configuration.getProperty(VAULT_TRUST_STORE_FILE_PASSWORD);

        if (vaultTrustStoreFile != null) {
            try {
                LOG.error("[vault] using trustStoreFile={}", vaultTrustStoreFile);
                File trustFile = new File(vaultTrustStoreFile);
                LOG.error("[vault] trustStoreFile exists={}, readable={}, size={}",
                        trustFile.exists(), trustFile.canRead(), trustFile.length());

                // NEW: load JKS with password, then provide in-memory KeyStore to the driver
                try (FileInputStream in = new FileInputStream(trustFile)) {
                    KeyStore ts = KeyStore.getInstance("JKS"); // keep default type
                    if (vaultTrustStoreFilePassword == null) {
                        throw new ConfigurationException("vault.trustStorePassword is required for JKS truststores");
                    }
                    ts.load(in, vaultTrustStoreFilePassword.toCharArray());
                    sslConfig.trustStore(ts);
                }

                LOG.error("[vault] trustStore (JKS) loaded and applied successfully");
            } catch (Exception e) {
                LOG.error("[vault] error setting trustStore (JKS): {}", e.getMessage(), e);
                throw new ConfigurationException("Encountered error while building ssl configuration: " + e.getMessage());
            }
        } else  {
            final String vaultPemFile = configuration.getProperty(VAULT_PEM_FILE);
            if (vaultPemFile != null) {
                try {
                    LOG.error("[vault] using pemFile={}", vaultPemFile);
                    sslConfig.pemFile(new File(vaultPemFile));
                }
                catch (VaultException e) {
                    LOG.error("[vault] error setting pemFile: {}", e.getMessage(), e);
                    throw new ConfigurationException(
                            String.format("Encountered error while building "
                                            + "ssl configuration: %s",
                                    e.getMessage())
                    );
                }
            }
        }

        if (configuration.getProperty(VAULT_AUTH_BACKEND).equals(CERT)) {
            final String vaultKeyStoreFile = configuration.getProperty(VAULT_KEY_STORE_FILE);
            final String vaultKeyStoreFilePassword = configuration.getProperty(VAULT_KEY_STORE_FILE_PASSWORD);
            if (vaultKeyStoreFile != null && vaultKeyStoreFilePassword != null) {
                try {
                    sslConfig.keyStoreFile(new File(vaultKeyStoreFile), vaultKeyStoreFilePassword);
                } catch (VaultException e) {
                    throw new ConfigurationException(String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
                }
            } else {
                final String vaultClientPemFile = configuration.getProperty(VAULT_CLIENT_PEM_FILE);
                final String vaultClientKeyPemFile = configuration.getProperty(VAULT_CLIENT_KEY_PEM_FILE);
                if (vaultClientPemFile != null && vaultClientKeyPemFile != null) {
                    try {
                        LOG.error("[vault] using keyStoreFile={}", vaultKeyStoreFile);
                        sslConfig.clientPemFile(new File(vaultClientPemFile))
                                .clientKeyPemFile(new File(vaultClientKeyPemFile));
                    } catch (VaultException e) {
                        LOG.error("[vault] error setting client cert/key: {}", e.getMessage(), e);
                        throw new ConfigurationException(String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
                    }
                }
            }
        }

        try {
            sslConfig.build();
        } catch (VaultException e) {
            LOG.error("[vault] error building SslConfig: {}", e.getMessage(), e);
            throw new ConfigurationException(String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
        }

        return sslConfig;
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
                throw new ConfigurationException(
                        String.format(
                                msg,
                                VAULT_TOKEN,
                                vaultAuthBackend
                        )
                );

            }
            return authToken;
        }

        final VaultConfig vaultAuthConfig = getVaultConfig();

        if(vaultAuthNameSpace!=null && !vaultAuthNameSpace.isEmpty()){
            vaultAuthConfig.nameSpace(vaultAuthNameSpace);
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
                            String.format(
                                    msg,
                                    String.join(", ",
                                            new String[]{VAULT_APPROLE_ID,
                                                    VAULT_APPROLE_SECRET_ID}),
                                    vaultAuthBackend
                            )
                    );
                }

                try {
                    authToken = vaultAuth.loginByAppRole(
                            vaultApproleAuthMount,
                            vaultApproleId,
                            vaultApproleSecretId).getAuthClientToken();
                    LOG.error("[vault] AppRole login success? {}", (authToken != null));

                } catch (VaultException e) {
                    LOG.error("[vault] AppRole login failed: {}", e.getMessage(), e);
                    throw new ConfigurationException(
                            String.format("Encountered error while authenticating with %s: %s", vaultAuthBackend, e.getLocalizedMessage())
                    );
                }
                break;

            case GITHUB:
                LOG.error("[vault] auth=GITHUB");
                final String vaultGithubToken = configuration.getProperty(VAULT_GITHUB_TOKEN);
                if (vaultGithubToken == null) {
                    LOG.error("[vault] missing github token");
                    throw new ConfigurationException(
                            String.format(msg,
                                    VAULT_GITHUB_TOKEN,
                                    vaultAuthBackend
                            )
                    );
                }

                try {
                    authToken = vaultAuth
                            .loginByGithub(vaultGithubToken)
                            .getAuthClientToken();
                    LOG.error("[vault] GitHub login success? {}", (authToken != null));

                } catch (VaultException e) {
                    LOG.error("[vault] GitHub login failed: {}", e.getMessage(), e);
                    throw new ConfigurationException(
                            String.format("Encountered error while authenticating with %s",
                                    vaultAuthBackend)
                    );
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
                                    vaultAuthBackend
                            )
                    );
                }

                try {
                    authToken = vaultAuth
                            .loginByUserPass(vaultUsername, vaultPassword, vaultUserpassAuthMount)
                            .getAuthClientToken();
                    LOG.error("[vault] UserPass login success? {}", (authToken != null));

                } catch (VaultException e) {
                    LOG.error("[vault] UserPass login failed: {}", e.getMessage(), e);
                    throw new ConfigurationException(
                            String.format("Encountered error while authenticating with %s",
                                    vaultAuthBackend)
                    );
                }
                break;

            case CERT:
                LOG.error("[vault] auth=CERT");
                final String configured = configuration.getProperty(VAULT_CERT_AUTH_MOUNT);
                final String mount = (configured == null || configured.isEmpty()) ? "cert" : configured;
                try {
                    authToken = vaultAuth.loginByCert(mount).getAuthClientToken();

                } catch (VaultException e) {
                    LOG.error("[vault] Cert login failed: {}", e.getMessage(), e);
                    throw new ConfigurationException(
                            String.format("Encountered error while authenticating with %s at mount '%s': %s",
                                    vaultAuthBackend, mount, e.getLocalizedMessage()));
                }
                break;


            default:
                LOG.error("[vault] unsupported auth backend='{}'", vaultAuthBackend);
                throw new ConfigurationException(
                        String.format("Unsupported auth backend: %s", vaultAuthBackend));

        }
        return authToken;
    }
}
