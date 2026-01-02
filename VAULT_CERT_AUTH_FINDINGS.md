# Vault TLS Certificate Authentication - Analysis and Findings

## Executive Summary

TLS Certificate authentication **IS supported** in the Rundeck Vault Storage Plugin, but there is a critical bug that causes authentication failures to be silently ignored, resulting in null pointer errors. The documentation has been significantly improved to provide clear guidance on certificate configuration.

## Critical Bug Identified

### Location
`VaultStoragePlugin.java` lines 348-355

### Issue
The `loginVault()` method silently catches and ignores all exceptions:

```java
private void loginVault(VaultClientProvider provider){
    try{
        vaultClient = provider.getVaultClient();
        vault = vaultClient.logical();
    }
    catch (Exception ignored){
        // BUG: Exception is silently ignored!
    }
}
```

### Impact
When TLS certificate authentication fails:
1. The exception is caught and silently ignored
2. `vaultClient` remains `null`
3. Later operations call `getVaultClient()` which returns `null`
4. This causes the error: `Cannot invoke "io.github.jopenlibs.vault.Vault.auth()" because the return value of "io.github.valfadeev.rundeck.plugin.vault.VaultStoragePlugin.getVaultClient()" is null`
5. Customer sees no useful error message and no traffic to Vault

### Recommended Fix

```java
private void loginVault(VaultClientProvider provider) throws ConfigurationException {
    try{
        vaultClient = provider.getVaultClient();
        vault = vaultClient.logical();
        LOG.debug("[vault] Successfully logged in and initialized vault client");
    }
    catch (ConfigurationException e) {
        LOG.error("[vault] Failed to login to Vault: {}", e.getMessage(), e);
        throw e;  // Re-throw to propagate the error with full details
    }
    catch (Exception e) {
        LOG.error("[vault] Unexpected error during Vault login: {}", e.getMessage(), e);
        throw new ConfigurationException("Failed to connect to Vault: " + e.getMessage());
    }
}
```

## TLS Certificate Configuration Explained

### Two Types of Certificates

The plugin uses certificates for two distinct purposes:

#### 1. Client Authentication Certificates (when authBackend=cert)
These authenticate Rundeck to Vault. Choose ONE option:

**Option A: Java KeyStore (JKS)**
- `keyStoreFile` - JKS file with client cert + private key
- `keyStoreFilePassword` - keystore password

**Option B: PEM Files**
- `clientPemFile` - client certificate in PEM format
- `clientKeyPemFile` - client private key in PEM format

#### 2. Server Trust Certificates (SSL Verification)
These verify the Vault server's identity. Choose ONE option:

**Option A: Java TrustStore (JKS)**
- `trustStoreFile` - JKS file with Vault server's CA cert
- `trustStoreFilePassword` - truststore password

**Option B: PEM Files**
- `pemFile` - Vault server's CA certificate in PEM format

### Additional Parameter
- `certAuthMount` - The mount path where TLS cert auth is enabled in Vault (default: "cert")

### Important Notes

1. **Production environments typically need BOTH**: client authentication certs AND server trust certs
2. **Do not mix formats**: Use either JKS or PEM for each purpose, not both
3. **File paths must be absolute** and accessible by the Rundeck process
4. **PEM files must be unencrypted** with UTF-8 encoding
5. **Client certificate must be registered** in Vault's TLS Certificate auth backend

## Documentation Improvements Made

Updated `/Users/forrest/Documents/GitHub/docs/docs/manual/key-storage/storage-plugins/vault.md` with:

1. **Clear section structure** separating client auth certs from server trust certs
2. **Added certAuthMount parameter** documentation (was missing)
3. **Two complete working examples**:
   - JKS format configuration example
   - PEM format configuration example
4. **Requirements checklist** for TLS cert authentication
5. **Explicit explanations** of what each file should contain
6. **Links to Vault documentation** for reference

## Testing Recommendations

### For LSEG Customer

1. **Check file accessibility**:
   ```bash
   # Run as the rundeck user
   ls -la /path/to/client-keystore.jks
   ls -la /path/to/truststore.jks
   ```

2. **Verify certificate contents**:
   ```bash
   # For JKS keystore
   keytool -list -v -keystore /path/to/client-keystore.jks
   
   # For JKS truststore
   keytool -list -v -keystore /path/to/truststore.jks
   
   # For PEM files
   openssl x509 -in /path/to/client-cert.pem -text -noout
   openssl rsa -in /path/to/client-key.pem -check
   ```

3. **Check Vault TLS cert auth configuration**:
   ```bash
   vault auth list
   vault read auth/cert/certs/your-cert-name
   ```

4. **Enable debug logging** in Rundeck to see detailed error messages:
   Add to `log4j2.properties`:
   ```
   logger.vault.name = io.github.valfadeev.rundeck.plugin.vault
   logger.vault.level = debug
   ```

5. **Verify network connectivity**:
   ```bash
   # Test TLS handshake with client cert
   openssl s_client -connect vault.example.com:8200 \
     -cert /path/to/client-cert.pem \
     -key /path/to/client-key.pem \
     -CAfile /path/to/vault-ca.pem
   ```

## Code Review Findings

### Supported Features ✅
- TLS Certificate authentication (cert backend)
- JKS keystore format
- PEM certificate format
- Custom cert auth mount paths
- Namespace support with cert auth

### Code Quality Issues ⚠️
1. **Critical**: Silent exception swallowing in `loginVault()` method
2. **Minor**: Inconsistent null checking in properties
3. **Minor**: Empty catch blocks make debugging difficult

### VaultClientProvider.java Analysis

The `VaultClientProvider.getVaultAuthToken()` method (lines 295-308) properly implements cert authentication:

```java
case CERT:
    LOG.debug("[vault] auth=CERT");
    final String configured = configuration.getProperty(VAULT_CERT_AUTH_MOUNT);
    final String mount = (configured == null || configured.isEmpty()) ? "cert" : configured;
    try {
        authToken = vaultAuth.loginByCert(mount).getAuthClientToken();
    } catch (VaultException e) {
        LOG.debug("[vault] Cert login failed: {}", e.getMessage(), e);
        throw new ConfigurationException(
                String.format("Encountered error while authenticating with %s at mount '%s': %s",
                        vaultAuthBackend, mount, e.getLocalizedMessage()));
    }
    break;
```

This code correctly:
- Uses the configured `certAuthMount` or defaults to "cert"
- Logs the authentication attempt
- Throws a descriptive ConfigurationException on failure

**However**, this exception is then caught and silently ignored by the caller (`loginVault()`), which is the bug.

## Next Steps

### For Plugin Development Team
1. **Fix the critical bug** in `loginVault()` method
2. **Add unit tests** specifically for cert authentication failure scenarios
3. **Consider adding validation** for cert file existence and readability at configuration time
4. **Add more detailed logging** throughout the authentication flow

### For Documentation Team
- Documentation has been updated and is ready for review
- Consider adding a troubleshooting section for common cert auth issues

### For Support Team
When assisting customers with cert authentication:
1. Enable debug logging first
2. Check service.log for actual error messages (once bug is fixed)
3. Verify file permissions and paths
4. Confirm cert is registered in Vault
5. Test cert authentication directly with Vault CLI first

## References

- [HashiCorp Vault TLS Certificate Auth Documentation](https://developer.hashicorp.com/vault/docs/auth/cert)
- [BetterCloud/vault-java-driver](https://github.com/BetterCloud/vault-java-driver) (underlying library)
- Updated documentation: `/docs/manual/key-storage/storage-plugins/vault.md`

---

**Report Date**: December 12, 2025  
**Analyzed By**: AI Assistant  
**Plugin Version**: Based on latest main branch  
**Affected Customers**: LSEG (and potentially others using cert authentication)

