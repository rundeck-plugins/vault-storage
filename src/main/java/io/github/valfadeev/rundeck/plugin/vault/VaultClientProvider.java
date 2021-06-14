package io.github.valfadeev.rundeck.plugin.vault;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import com.bettercloud.vault.SslConfig;
import com.bettercloud.vault.Vault;
import com.bettercloud.vault.VaultConfig;
import com.bettercloud.vault.VaultException;
import com.bettercloud.vault.api.Auth;
import com.dtolabs.rundeck.core.plugins.configuration.ConfigurationException;

import static io.github.valfadeev.rundeck.plugin.vault.ConfigOptions.*;
import static io.github.valfadeev.rundeck.plugin.vault.SupportedAuthBackends.*;

class VaultClientProvider {

    private Properties configuration;
    protected static final String K8S_SERVICE_ACCOUNT_TOKEN = "/var/run/secrets/kubernetes.io/serviceaccount/token";

    VaultClientProvider(Properties configuration) {
        this.configuration = configuration;
    }

    Vault getVaultClient() throws ConfigurationException {
        final Integer vaultMaxRetries = Integer.parseInt(configuration.getProperty(VAULT_MAX_RETRIES));
        final Integer vaultRetryIntervalMilliseconds = Integer.parseInt(configuration.getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS));
        final Integer vaultEngineVersion = Integer.parseInt(configuration.getProperty(VAULT_ENGINE_VERSION));

        VaultConfig vaultConfig = getVaultConfig();

        try {
            String authToken = getVaultAuthToken();
            vaultConfig.token(authToken).build();
            return new Vault(vaultConfig, vaultEngineVersion)
                    .withRetries(vaultMaxRetries,
                            vaultRetryIntervalMilliseconds);
        } catch (VaultException e) {
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
                throw new ConfigurationException(
                        String.format("Encountered error while building namespace configuration: %s", e.getMessage()));
            }
        }

        return vaultConfig;
    }

    private SslConfig getSslConfig() throws ConfigurationException {
        SslConfig sslConfig = new SslConfig();

        final Boolean vaultVerifySsl = Boolean.parseBoolean(configuration.getProperty(VAULT_VERIFY_SSL));
        sslConfig.verify(vaultVerifySsl);

        final String vaultTrustStoreFile = configuration.getProperty(VAULT_TRUST_STORE_FILE);
        if (vaultTrustStoreFile != null) {
            try {
                sslConfig.trustStoreFile(new File(vaultTrustStoreFile));
            } catch (VaultException e) {
                throw new ConfigurationException(String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
            }
        } else  {
            final String vaultPemFile = configuration.getProperty(VAULT_PEM_FILE);
            if (vaultPemFile != null) {
                try {
                    sslConfig.pemFile(new File(vaultPemFile));
                }
                catch (VaultException e) {
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
                        sslConfig.clientPemFile(new File(vaultClientPemFile))
                                .clientKeyPemFile(new File(vaultClientKeyPemFile));
                    } catch (VaultException e) {
                        throw new ConfigurationException(String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
                    }
                }
            }
        }

        try {
            sslConfig.build();
        } catch (VaultException e) {
            throw new ConfigurationException(String.format("Encountered error while building ssl configuration: %s", e.getMessage()));
        }

        return sslConfig;
    }

    private String getVaultAuthToken() throws ConfigurationException {
        final String vaultAuthBackend = configuration.getProperty(VAULT_AUTH_BACKEND);

        final String authToken;
        final String msg = "Must specify %s when auth backend is %s";

        if (vaultAuthBackend.equals(TOKEN)) {
            authToken = configuration.getProperty(VAULT_TOKEN);
            if (authToken == null) {
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
        final Auth vaultAuth = new Vault(vaultAuthConfig).auth();

        switch (vaultAuthBackend) {

            case APPROLE:
                final String vaultApproleId = configuration.getProperty(VAULT_APPROLE_ID);
                final String vaultApproleSecretId = configuration.getProperty(VAULT_APPROLE_SECRET_ID);
                final String vaultApproleAuthMount = configuration.getProperty(VAULT_APPROLE_AUTH_MOUNT);

                if (vaultApproleId == null || vaultApproleSecretId == null) {
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

                } catch (VaultException e) {
                    throw new ConfigurationException(
                            String.format("Encountered error while authenticating with %s",
                                    vaultAuthBackend)
                    );
                }
                break;

            case GITHUB:
                final String vaultGithubToken = configuration.getProperty(VAULT_GITHUB_TOKEN);
                if (vaultGithubToken == null) {
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

                } catch (VaultException e) {
                    throw new ConfigurationException(
                            String.format("Encountered error while authenticating with %s",
                                    vaultAuthBackend)
                    );
                }
                break;

            case USERPASS:
                final String vaultUsername = configuration.getProperty(VAULT_USERNAME);
                final String vaultPassword = configuration.getProperty(VAULT_PASSWORD);
                if (vaultUsername == null || vaultPassword == null) {
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
                            .loginByUserPass(vaultUsername, vaultPassword)
                            .getAuthClientToken();

                } catch (VaultException e) {
                    throw new ConfigurationException(
                            String.format("Encountered error while authenticating with %s",
                                    vaultAuthBackend)
                    );
                }
                break;

            case KUBERNETES:
                final String vaultRole = configuration.getProperty(VAULT_ROLE);
                String vaultK8sToken = "";
                try {
                    vaultK8sToken = Files.readString(Path.of(K8S_SERVICE_ACCOUNT_TOKEN), StandardCharsets.US_ASCII);
                }  catch (IOException e) {
                    throw new ConfigurationException(
                            String.format("Rundeck should be running in Pod for Kubernetes authentication type.")
                    );
                }

                try {

                    authToken = vaultAuth
                            .loginByKubernetes(vaultRole, vaultK8sToken)
                            .getAuthClientToken();

                } catch (VaultException e) {
                    throw new ConfigurationException(
                            String.format("Encountered error while authenticating with %s",
                                    vaultAuthBackend)
                    );
                }
                break;
            default:
                throw new ConfigurationException(
                        String.format("Unsupported auth backend: %s", vaultAuthBackend));

        }
        return authToken;
    }
}
