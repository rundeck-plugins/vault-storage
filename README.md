# Rundeck Vault Storage Plugin

## Purpose
This is a [Storage Backend](https://docs.rundeck.com/docs/administration/security/key-storage.html#key-data-storage-converter) plugin for storing Key Store data in [Vault](https://www.vaultproject.io/).

This plugin is bundled with Rundeck Enterprise.  It is also available to Community users following the install steps below.

## Community Installation
  * Download and start [Rundeck](http://rundeck.org/downloads.html). It will automatically create the necessary directories.
  * Clone this repository. Build using `gradle` wrapper:
    ```
      ./gradlew clean build
    ```
  * Drop `rundeck-vault-plugin-<version>.jar` to `libext/` under Rundeck installation directory.
  * Restart Rundeck.

## Configuration

Add the settings to $RDECK_BASE/etc/rundeck-config.properties

* **prefix**: Vault Prefix in Vault secret backend

```rundeck.storage.provider.[index].config.prefix=rundeck```

* **address**: Vault Address of the Vault server

```rundeck.storage.provider.[index].config.address=https://vaultURL:8200```

* **authBackend**: Vault Authentication backend

```
rundeck.storage.provider.[index].config.authBackend=authBackend
```

Default value: token

Allowed values: approle, cert, github, token, userpass

* **token**: Vault authentication token. Required, if authentication backend is 'token'

```rundeck.storage.provider.[index].config.token=xxxxxx```


* **username**: User name. Required for user/password and LDAP authentication backend

```
rundeck.storage.provider.[index].config.username=username
```

* **password**: Password. Required for user/password and LDAP authentication backend
```
rundeck.storage.provider.[index].config.password=password
```

* **approleId**:  AppRole role ID. The role-id used for authentication
```
rundeck.storage.provider.[index].config.approleId=approleId
```

* **approleSecretId**:  AppRole secret ID. The secret-id used for authentication

```
rundeck.storage.provider.[index].config.approleSecretId=approleSecretId
```

* **approleAuthMount**:  AppRole mount name. The mount name of the AppRole authentication back end
```
rundeck.storage.provider.[index].config.approleAuthMount=approleAuthMount
```

* **githubToken**: GitHub token. The app-id used for authentication
```
rundeck.storage.provider.[index].config.githubToken=githubToken
```


* **namespace**: Namespace. Vault namespace (Optional)
```
rundeck.storage.provider.[index].config.namespace=namespace
```

* **authNamespace**: Authentication Namespace. Vault authentication namespace used for authentication(Optional)
```
rundeck.storage.provider.[index].config.authNamespace=namespace
```
* **certAuthMount**:  Cert Auth Mount name, The mount name of the TLS Certificate authentication back end for cert authentication.
```
rundeck.storage.provider.[index].config.certAuthMount=mount-name
```

* **keyStoreFile**: Key store file
A Java keystore, containing a client certificate that's registered with Vault's TLS Certificate auth backend.

```
rundeck.storage.provider.[index].config.keyStoreFile=/path/keyfile
```

* **keyStoreFilePassword**: Key store password
The password needed to access the keystore

```
rundeck.storage.provider.[index].config.keyStoreFilePassword=/path/keyStoreFilePassword
```

* **trustStoreFile**: Truststore file. A JKS truststore file, containing the Vault server's X509 certificate
```
rundeck.storage.provider.[index].config.trustStoreFile=/path/trustStoreFile
```
* **trustStoreFilePassword**: Truststore file password. The password needed to access the truststore.
```
rundeck.storage.provider.[index].config.trustStoreFile=/path/trustStoreFile
```

* **pemFile**: PEM file. The path of a file containing an X.509 certificate, in unencrypted PEM format with UTF-8 encoding.

```
rundeck.storage.provider.[index].config.pemFile=/path/pemFile
```

* **clientPemFile**: Client PEM file. The path of a file containing an X.509 certificate, in unencrypted PEM format with UTF-8 encoding.

```
rundeck.storage.provider.[index].config.clientPemFile=/path/clientPemFile
```

* **clientKeyPemFile**: Client key PEM file. The path of a file containing an RSA private key, in unencrypted PEM format with UTF-8 encoding.

```
rundeck.storage.provider.[index].config.clientKeyPemFile=/path/clientKeyPemFile
```

* **validateSsl**:  Enable/Disable SSL validation. Specifies whether SSL validation is to be performed
```
rundeck.storage.provider.[index].config.validateSsl=true/false
```
Default value: true

* **maxRetries**:  Max retries. Maximum number of connection retries to Vault server
```
rundeck.storage.provider.[index].config.maxRetries=5
```

Default value: 5

* **retryIntervalMilliseconds**:  Retry interval. Connection retry interval, ms
```
rundeck.storage.provider.[index].config.retryIntervalMilliseconds=1000
```

Default value: 1000

* **openTimeout**:  Open timeout. Connection opening timeout, in seconds
```
rundeck.storage.provider.[index].config.openTimeout=5
```

Default value: 5

* **readTimeout**:  Read timeout. Response read timeout, in seconds

```
rundeck.storage.provider.[index].config.readTimeout=20
```

Default value: 20

* **secretBackend**:  Secret Backend. The secret backend to use in vault

```
rundeck.storage.provider.[index].config.secretBackend=secret
```

Default value: secret

* **storageBehaviour**:  Storage Behaviour. Use the default Rundeck Behaviour for key storage (with rundeck headers) or use just the key/value behaviour from vault. Options are: rundeck, vault
```
rundeck.storage.provider.[index].config.storageBehaviour=vault/rundeck
```
Default value: rundeck

* **engineVersion**: Vault Engine Version Key/Value Secret Engine Config

```
rundeck.storage.provider.[index].config.engineVersion=1/2
```

Default value: 1

### Configuration Examples


#### **example basic settings**
```
rundeck.storage.provider.1.type=vault-storage
rundeck.storage.provider.1.path=keys
rundeck.storage.provider.1.config.prefix=rundeck
rundeck.storage.provider.1.config.secretBackend=secret
rundeck.storage.provider.1.config.address=$VAULT_URL
rundeck.storage.provider.1.config.token=$VAULT_TOKEN
```

#### **existing vault storage**

For existing vault storage, probably you will need to remove the default `keys` path added by default for rundeck.
You can use these settings for an existing vault storage:

```
rundeck.storage.provider.1.type=vault-storage
rundeck.storage.provider.1.path=keys
rundeck.storage.provider.1.config.prefix=someprefix
rundeck.storage.provider.1.config.secretBackend=mybackend
rundeck.storage.provider.1.config.address=$VAULT_URL
rundeck.storage.provider.1.config.token=$VAULT_TOKEN
rundeck.storage.provider.1.config.storageBehaviour=vault
```

#### **Using APPROLE authentication**

You can use these settings for an existing vault storage:

```
rundeck.storage.provider.1.type=vault-storage
rundeck.storage.provider.1.path=keys
rundeck.storage.provider.1.config.prefix=app
rundeck.storage.provider.1.config.secretBackend=secret
rundeck.storage.provider.1.config.address=$VAULT_URL
rundeck.storage.provider.1.config.engineVersion=2
rundeck.storage.provider.1.config.storageBehaviour=vault

#auth
rundeck.storage.provider.1.config.authBackend=approle
rundeck.storage.provider.1.config.approleAuthMount=approle
rundeck.storage.provider.1.config.approleId=$VAULT_APPROLE_ID
rundeck.storage.provider.1.config.approleSecretId=$VAULT_APPROLE_SECRET_ID

#timeouts
rundeck.storage.provider.1.config.maxRetries=500
rundeck.storage.provider.1.config.retryIntervalMilliseconds=2
rundeck.storage.provider.1.config.openTimeout=2500
rundeck.storage.provider.1.config.readTimeout=2500
```

**Enabling APPROLE Vault using API**

```
curl --header "X-Vault-Token: $TOKEN" --request POST --data '{"type": "approle"}' http://localhost:8200/v1/sys/auth/approle
curl --header "X-Vault-Token: $TOKEN" --request POST --data '{"policies": "rundeck", "token_ttl": "2m", "token_max_ttl": "2m"}' http://localhost:8200/v1/auth/approle/role/rundeck
# get $VAULT_APPROLE_ID
curl --header "X-Vault-Token: $TOKEN" http://localhost:8200/v1/auth/approle/role/rundeck/role-id | jq
# get $VAULT_APPROLE_SECRET_ID
curl --header "X-Vault-Token: $TOKEN" --request POST http://localhost:8200/v1/auth/approle/role/rundeck/secret-id | jq
```

#### **Using CERT authentication**

```
rundeck.storage.provider.1.type=vault-storage
rundeck.storage.provider.1.path=keys
rundeck.storage.provider.1.config.prefix=app
rundeck.storage.provider.1.config.address=$VAULT_URL
rundeck.storage.provider.1.config.authBackend=cert
rundeck.storage.provider.1.config.secretBackend=kv
rundeck.storage.provider.1.config.engineVersion=2
rundeck.storage.provider.1.config.certAuthMount=tls-auth
rundeck.storage.provider.1.config.keyStoreFile=$KEYSTORE_FILE
rundeck.storage.provider.1.config.keyStoreFilePassword=$KEYSTORE_PASSWORD
rundeck.storage.provider.1.config.trustStoreFile=$TRUSTSTORE_FILE
rundeck.storage.provider.1.config.truststoreFilePassword=$TRUSTSTORE_PASSWORD
rundeck.storage.provider.1.config.validateSsl=true
```
## Vault API versions

Since version 1.3.1, this plugin can work with `kV Secrets Engine - Version 2`. 
A new config variable was added in order to set the API version that you need to use:

rundeck.storage.provider.1.config.engineVersion=1/2

* engineVersion=1 will work with vault version 0.x
* engineVersion=2 will work with vault version 1.x

Example:

```
rundeck.storage.provider.1.type=vault-storage
rundeck.storage.provider.1.path=keys
rundeck.storage.provider.1.config.prefix=rundeck
rundeck.storage.provider.1.config.secretBackend=secret
rundeck.storage.provider.1.config.address=$VAULT_URL
rundeck.storage.provider.1.config.token=$VAULT_TOKEN
rundeck.storage.provider.1.config.engineVersion=2
```

By default, the value is set to v1 (1)


## Minimal version requirements
  * Java 1.8
  * Rundeck 2.10.0
  * Vault 0.9.0

## Thanks
  * [BetterCloud/vault-java-driver](https://github.com/BetterCloud/vault-java-driver) made this possible.

## TODO
  * Automated auth token lease renewal
  * Storage converter plugin




