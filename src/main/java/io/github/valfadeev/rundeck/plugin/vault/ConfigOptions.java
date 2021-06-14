package io.github.valfadeev.rundeck.plugin.vault;

class ConfigOptions {
    static final String VAULT_PREFIX = "prefix";
    static final String VAULT_ADDRESS = "address";
    static final String VAULT_TOKEN = "token";
    static final String VAULT_NAMESPACE = "namespace";
    static final String VAULT_PEM_FILE = "pemFile";
    static final String VAULT_VERIFY_SSL = "validateSsl";
    static final String VAULT_MAX_RETRIES = "maxRetries";
    static final String VAULT_RETRY_INTERVAL_MILLISECONDS = "retryIntervalMilliseconds";
    static final String VAULT_OPEN_TIMEOUT = "openTimeout";
    static final String VAULT_READ_TIMEOUT = "readTimeout";
    static final String VAULT_AUTH_BACKEND = "authBackend";
    static final String VAULT_KEY_STORE_FILE = "keyStoreFile";
    static final String VAULT_KEY_STORE_FILE_PASSWORD = "keyStoreFilePassword";
    static final String VAULT_TRUST_STORE_FILE = "trustStoreFile";
    static final String VAULT_CLIENT_PEM_FILE = "clientPemFile";
    static final String VAULT_CLIENT_KEY_PEM_FILE = "clientKeyPemFile";
    static final String VAULT_USERNAME = "username";
    static final String VAULT_PASSWORD = "password";
    static final String VAULT_GITHUB_TOKEN = "githubToken";
    static final String VAULT_APPROLE_AUTH_MOUNT = "approleAuthMount";
    static final String VAULT_APPROLE_ID = "approleId";
    static final String VAULT_APPROLE_SECRET_ID = "approleSecretId";
    static final String VAULT_SECRET_BACKEND = "secretBackend";
    static final String VAULT_STORAGE_BEHAVIOUR = "storageBehaviour";
    static final String VAULT_ENGINE_VERSION = "engineVersion";
    static final String VAULT_ROLE = "role";
}
