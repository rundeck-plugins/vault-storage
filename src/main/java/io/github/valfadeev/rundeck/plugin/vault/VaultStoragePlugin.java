package io.github.valfadeev.rundeck.plugin.vault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import io.github.jopenlibs.vault.Vault;
import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.response.LookupResponse;
import com.dtolabs.rundeck.core.plugins.Plugin;
import com.dtolabs.rundeck.core.plugins.configuration.*;
import com.dtolabs.rundeck.core.storage.ResourceMeta;
import com.dtolabs.rundeck.plugins.ServiceNameConstants;
import com.dtolabs.rundeck.plugins.descriptions.*;
import com.dtolabs.rundeck.plugins.storage.StoragePlugin;
import org.rundeck.storage.api.Path;
import org.rundeck.storage.api.PathUtil;
import org.rundeck.storage.api.Resource;
import org.rundeck.storage.api.StorageException;
import org.rundeck.storage.impl.ResourceBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.github.valfadeev.rundeck.plugin.vault.ConfigOptions.*;

/**
 * {@link VaultStoragePlugin} that stores Key Store data in Vault
 *
 * @author ValFadeev
 * @since 2017-09-18
 */
@Plugin(name = "vault-storage", service = ServiceNameConstants.Storage)
@PluginDescription(title = "Vault Storage", description = "Use Hashicorp Vault as a storage layer")
public class VaultStoragePlugin implements StoragePlugin {
    private static final Logger LOG = LoggerFactory.getLogger(VaultStoragePlugin.class);

    java.util.logging.Logger log = java.util.logging.Logger.getLogger("vault-storage");

    public VaultStoragePlugin() {}

    protected static final String VAULT_STORAGE_KEY = "data";
    protected static final String RUNDECK_DATA_TYPE = "Rundeck-data-type";
    protected static final String RUNDECK_KEY_TYPE = "Rundeck-key-type";
    protected static final String RUNDECK_CONTENT_MASK = "Rundeck-content-mask";
    protected static final String PRIVATE_KEY_MIME_TYPE = "application/octet-stream";
    protected static final String PUBLIC_KEY_MIME_TYPE = "application/pgp-keys";
    protected static final String PASSWORD_MIME_TYPE = "application/x-rundeck-data-password";

    public static final int MAX_GUARANTEED_VALIDITY_SECONDS = 60;

    private Logical vault;
    private int guaranteedTokenValidity;
    //if is true, objects will be saved with rundeck default headers behaivour
    private boolean rundeckObject=true;
    private VaultClientProvider clientProvider;
    private Vault vaultClient;
    Properties properties = new Properties();

    @PluginProperty(title = "vaultPrefix", description = "username for the account to authenticate to")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Basic Config")
    String prefix;

    @PluginProperty(title = "Vault address", description = "Address of the Vault server", defaultValue = "https://localhost:8200")
    @RenderingOptions({
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Basic Config")
    })
    String address;

    @SelectValues(values = { "token", "approle", "cert" , "github", "userpass"})
    @PluginProperty(title = "Vault auth backend", description = "Authentication backend", defaultValue = "token")
    @RenderingOptions({
            @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Basic Config")
    })
    String authBackend;


    @PluginProperty(title = "Vault token", description = "Vault authentication token. " + "Required, if authentication backend is 'token'")
    @RenderingOptions({
            @RenderingOption(key = StringRenderingConstants.DISPLAY_TYPE_KEY, value = "PASSWORD"),
            @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Authentication")
    })
    String token;

    @PluginProperty(title = "AppRole role ID", description = "The role-id used for authentication")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "App Role Authentication")
    String approleId;

    @PluginProperty(title = "AppRole secret ID", description = "The secret-id used for authentication")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "App Role Authentication")
    String approleSecretId;

    @PluginProperty(title = "AppRole mount name", description = "The mount name of the AppRole authentication back end")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "App Role Authentication")
    String approleAuthMount;

    @PluginProperty(title = "Cert Auth Mount",
            description = "The mount name of the TLS Certificate authentication back end (e.g., tls-auth). Defaults to 'cert'.")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Authentication")
    String certAuthMount;

    @PluginProperty(title = "Key store file", description = "A Java keystore, containing a client certificate " + "that's registered with Vault's TLS Certificate auth backend.")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Authentication")
    String keyStoreFile;

    @PluginProperty(title = "Key store password", description = "The password needed to access the keystore", defaultValue = "")
    @RenderingOptions({
            @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Authentication"),
            @RenderingOption(key = StringRenderingConstants.DISPLAY_TYPE_KEY, value = "PASSWORD")
    })
    String keyStoreFilePassword;

    @PluginProperty(title = "Truststore file", description = "A JKS truststore file, containing the Vault " + "server's X509 certificate")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "SSL Config")
    String trustStoreFile;

    @PluginProperty(title = "Truststore password", description = "The password needed to access the truststore", defaultValue = "")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "SSL Config")
    String trustStoreFilePassword;

    @PluginProperty(title = "PEM file", description = "The path of a file containing an X.509 certificate, " + "in unencrypted PEM format with UTF-8 encoding.")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "SSL Config")
    String pemFile;

    @PluginProperty(title = "Client PEM file", description = "The path of a file containing an X.509 certificate, " + "in unencrypted PEM format with UTF-8 encoding.")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "SSL Config")
    String clientPemFile;

    @PluginProperty(title = "Client Key PEM file", description = "The path of a file containing an RSA private key, " + "in unencrypted PEM format with UTF-8 encoding.")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "SSL Config")
    String clientKeyPemFile;

    @PluginProperty(title = "Enable SSL validation", description = "Specifies whether SSL validation is to be performed", defaultValue = "true", required = true)
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "SSL Config")
    Boolean validateSsl;

    @PluginProperty(title = "Userpass Mount name", description = "The mount name of the Userpass authentication back end", defaultValue = "userpass")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Authentication")
    String userpassAuthMount;

    @PluginProperty(title = "User name", description = "Required for user/password and LDAP authentication backend")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Authentication")
    String username;

    @PluginProperty(title = "Password", description = "Required for user/password and LDAP authentication backend")
    @RenderingOptions({
            @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Authentication"),
            @RenderingOption(key = StringRenderingConstants.DISPLAY_TYPE_KEY, value = "PASSWORD")
    })
    String password;

    @PluginProperty(title = "GitHub token", description = "The app-id used for authentication")
    @RenderingOptions({
            @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Authentication"),
            @RenderingOption(key = StringRenderingConstants.DISPLAY_TYPE_KEY, value = "PASSWORD")
    })
    String githubToken;

    @PluginProperty(title = "Max retries", description = "Maximum number of connection " + "retries to Vault server", defaultValue = "5")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Connection Config")
    String maxRetries;

    @PluginProperty(title = "Retry interval", description = "Connection retry interval, in ms", defaultValue = "1000")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Connection Config")
    String retryIntervalMilliseconds;

    @PluginProperty(title = "Open timeout", description = "Connection opening timeout, in seconds", defaultValue = "5")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Connection Config")
    String openTimeout;

    @PluginProperty(title = "Read timeout", description = "Response read timeout, in seconds", defaultValue = "20")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Connection Config")
    String readTimeout;

    @PluginProperty(title = "Secret Backend", description = "The secret backend to use in vault", defaultValue = "secret")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Basic Config")
    String secretBackend;

    @PluginProperty(title = "Namespace", description = "The namespace to access and save the secrets")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Enterprise Config")
    String namespace;

    @PluginProperty(title = "storageBehaviour", description = "storageBehaviour for the account to authenticate to")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Basic Config")
    @SelectValues(freeSelect = false, values = { "vault", "rundeck"})
    String storageBehaviour;

    @PluginProperty(title = "Vault Engine Version", description = "Key/Value Secret Engine Config", defaultValue = "1")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Basic Config")
    @SelectValues(freeSelect = false, values = { "1", "2"})
    String engineVersion;

    @PluginProperty(title = "Authentication Namespace", description = "The namespace for authentication")
    @RenderingOption(key = StringRenderingConstants.GROUP_NAME, value = "Authentication")
    String authNamespace;

    protected Vault getVaultClient() throws ConfigurationException {
        //clone former properties configuration passes to configure method
        if(vaultClient == null || properties.isEmpty()) {

            if(secretBackend != null){
                properties.setProperty(VAULT_SECRET_BACKEND, secretBackend);
            }

            if(prefix != null){
                properties.setProperty(VAULT_PREFIX, prefix);
            }
            if(address != null){
                properties.setProperty(VAULT_ADDRESS, address);
            }
            if(token != null){
                properties.setProperty(VAULT_TOKEN, token);
            }
            if(authBackend != null){
                properties.setProperty(VAULT_AUTH_BACKEND, authBackend);
            }
            if(keyStoreFile != null){
                properties.setProperty(VAULT_KEY_STORE_FILE, keyStoreFile);
            }
            if(keyStoreFilePassword != null){
                properties.setProperty(VAULT_KEY_STORE_FILE_PASSWORD, keyStoreFilePassword);
            }
            if(trustStoreFile != null){
                properties.setProperty(VAULT_TRUST_STORE_FILE, trustStoreFile);
            }
            if(trustStoreFilePassword != null){
                properties.setProperty(VAULT_TRUST_STORE_FILE_PASSWORD, trustStoreFilePassword);
            }
            if (certAuthMount != null) {
                properties.setProperty(VAULT_CERT_AUTH_MOUNT, certAuthMount);
            }
            if(pemFile != null){
                properties.setProperty(VAULT_PEM_FILE, pemFile);
            }
            if(clientPemFile != null){
                properties.setProperty(VAULT_CLIENT_PEM_FILE, clientPemFile);
            }
            if(clientKeyPemFile != null){
                properties.setProperty(VAULT_CLIENT_KEY_PEM_FILE, clientKeyPemFile);
            }
            if(validateSsl != null){
                properties.setProperty(VAULT_VERIFY_SSL, validateSsl.toString());
            }
            if(userpassAuthMount != null){
                properties.setProperty(VAULT_USERPASS_AUTH_MOUNT, userpassAuthMount);
            }
            if(username != null){
                properties.setProperty(VAULT_USERNAME, username);
            }
            if(password != null){
                properties.setProperty(VAULT_PASSWORD, password);
            }
            if(approleId != null){
                properties.setProperty(VAULT_APPROLE_ID, approleId);
            }
            if(approleSecretId != null){
                properties.setProperty(VAULT_APPROLE_SECRET_ID, approleSecretId);
            }
            if(approleAuthMount != null){
                properties.setProperty(VAULT_APPROLE_AUTH_MOUNT, approleAuthMount);
            }
            if(githubToken != null){
                properties.setProperty(VAULT_GITHUB_TOKEN, githubToken);
            }
            if(maxRetries != null){
                properties.setProperty(VAULT_MAX_RETRIES, maxRetries);
            }
            if(retryIntervalMilliseconds != null){
                properties.setProperty(VAULT_RETRY_INTERVAL_MILLISECONDS, retryIntervalMilliseconds);
            }
            if(openTimeout != null){
                properties.setProperty(VAULT_OPEN_TIMEOUT, openTimeout);
            }
            if(readTimeout != null){
                properties.setProperty(VAULT_READ_TIMEOUT, readTimeout);
            }
            if(secretBackend != null){
                properties.setProperty(VAULT_SECRET_BACKEND, secretBackend);
            }
            if(namespace != null){
                properties.setProperty(VAULT_NAMESPACE, namespace);
            }
            if(storageBehaviour != null){
                properties.setProperty(VAULT_STORAGE_BEHAVIOUR, storageBehaviour);
            }
            if(engineVersion != null){
                properties.setProperty(VAULT_ENGINE_VERSION, engineVersion);
            }
            if(authNamespace != null){
                properties.setProperty(VAULT_AUTH_NAMESPACE, authNamespace);
            }

            //set member variables on object on entry, lookup -> getVaultClient()
            if (storageBehaviour != null && storageBehaviour.equals("vault")) {
                rundeckObject = false;
            }

            guaranteedTokenValidity = calculateGuaranteedTokenValidity(properties);

            clientProvider = getVaultClientProvider(properties);
            loginVault(clientProvider);
        }
            return vaultClient;

    }

    protected VaultClientProvider getVaultClientProvider(Properties configuration) {
        return new VaultClientProvider(configuration);
    }

    protected int calculateGuaranteedTokenValidity(Properties configuration) {
        return Integer.min(
                Integer.parseInt(configuration.getProperty(VAULT_MAX_RETRIES))
                        * (Integer.parseInt(configuration.getProperty(VAULT_READ_TIMEOUT))
                            + Integer.parseInt(configuration.getProperty(VAULT_OPEN_TIMEOUT))
                            + Integer.parseInt(configuration.getProperty(VAULT_RETRY_INTERVAL_MILLISECONDS)) / 1000),
                MAX_GUARANTEED_VALIDITY_SECONDS
        );
    }

    public static String getVaultPath(String rawPath, String vaultSecretBackend, String vaultPrefix) {
        return vaultPrefix != null && !vaultPrefix.isEmpty() ? String.format("%s/%s/%s", vaultSecretBackend, vaultPrefix, rawPath) : String.format("%s/%s", vaultSecretBackend, rawPath);
    }

    private boolean isDir(String key) {
        return key.endsWith("/");
    }

    protected void lookup(){
        try {
            LookupResponse lookupSelf = getVaultClient().auth().lookupSelf();
            if (lookupSelf.getTTL() <= guaranteedTokenValidity || lookupSelf.getNumUses() < 0) {
                loginVault(clientProvider);
            }
        } catch (VaultException e) {
            if(e.getHttpStatusCode() == 403){//try login again
                loginVault(clientProvider);
            } else {
                e.printStackTrace();
            }
        } catch (ConfigurationException e) {
            e.printStackTrace();
        }
    }

    private void loginVault(VaultClientProvider provider){
        try{
            vaultClient = provider.getVaultClient();
            vault = vaultClient.logical();
        }
        catch (Exception ignored){

        }
    }

    private boolean isVaultDir(String key) {

        try{
            lookup();
            List<String> list = getVaultList(key);
            if(list.size() > 0){
                return true;
            }else{
                if(!rundeckObject) {
                    //key/value with multiples keys
                    KeyObject object = this.getVaultObject(PathUtil.asPath(key));
                    if (!object.isRundeckObject() && object.isMultiplesKeys()) {
                        return true;
                    }
                }

                return false;
            }
        } catch (VaultException e) {
            log.info("error:" + e.getMessage());
            return false;
        }
    }

    private enum KeyType {
        RESOURCE,
        DIRECTORY,
        ALL
    }

    private void saveResource(Path path, ResourceMeta content, String event) {
        ByteArrayOutputStream baoStream = new ByteArrayOutputStream();
        try {
            content.writeContent(baoStream);
        } catch (IOException e) {
            LOG.error("Failed to extract resource content for path {} with event {}. Error: {}", path, event, e.getMessage(), e);
            throw new StorageException(
                    String.format("Encountered error while extracting "
                                    + "resource content: %s",
                            e.getMessage()),
                    StorageException.Event.valueOf(event.toUpperCase()),
                    path);
        }

        KeyObject object;
        if (event.equals("create")) {
            if (rundeckObject) {
                object = new RundeckKey(path);
                LOG.error("Created RundeckKey object for path {} with event {}", path, event);
            } else {
                object = new VaultKey(path, null);
                LOG.error("Created VaultKey object for path {} with event {}", path, event);
            }
        } else {
            object = this.getVaultObject(path);
            LOG.error("Retrieved existing VaultKey object for path {} with event {}", path, event);
        }

        Map<String, Object> payload = object.saveResource(content, event, baoStream);
        LOG.error("Generated payload for path {} with event {}: {}", path, event, payload);

        try {
            lookup();
            String vaultPath = getVaultPath(object.getPath().getPath(), secretBackend, prefix);
            LOG.error("Writing data to Vault at {} for path {} with event {}", vaultPath, path, event);
            vault.write(vaultPath, payload);
            LOG.error("Successfully wrote data to Vault at {} for path {} with event {}", vaultPath, path, event);
        } catch (VaultException e) {
            LOG.error("Failed to write data to Vault for path {} with event {}. Error: {}", path, event, e.getMessage(), e);
            throw new StorageException(
                    String.format("Encountered error while writing data to Vault %s",
                            e.getMessage()),
                    StorageException.Event.valueOf(event.toUpperCase()),
                    path);
        }
    }


    private Resource<ResourceMeta> loadDir(Path path) {
        return new ResourceBase<>(path, null, true);
    }

    private Resource<ResourceMeta> loadResource(Path path, String event) {
        KeyObject object = this.getVaultObject(path);
        return loadResource(object,event);
    }

    private Resource<ResourceMeta> loadResource(KeyObject object, String event) {

        if(object.isError()){
            throw new StorageException(
                    String.format("Encountered error while reading data from Vault %s",
                                  object.getErrorMessage()),
                    StorageException.Event.valueOf(event.toUpperCase()),
                    object.getPath());
        }

        return object.loadResource();


    }

    private Set<Resource<ResourceMeta>> listResources(Path path, KeyType type) {
        List<String> response;

        try {
            lookup();
            response = getVaultList(path);

        } catch (VaultException e) {
            throw StorageException.listException(
                    path,
                    String.format("Encountered error while reading data from Vault %s",
                            e.getMessage()));
        }

        Set<Resource<ResourceMeta>> resources = new HashSet<>();

        List<String> filtered;
        if (type.equals(KeyType.RESOURCE)) {
            filtered = response.stream().filter(k -> !isDir(k)).collect(Collectors.toList());
        } else if (type.equals(KeyType.DIRECTORY)) {
            filtered = response.stream().filter(this::isDir).collect(Collectors.toList());
        } else {
            filtered = response;
        }

        //vault object with multiples keys
        boolean isKeyMultipleValues=false;
        KeyObject multivalueObject = null;
        if(filtered.isEmpty() && !rundeckObject){
            multivalueObject = this.getVaultObject(path);
            if(!multivalueObject.isRundeckObject() && multivalueObject.isMultiplesKeys()){
                isKeyMultipleValues=true;
                filtered = new ArrayList<>(multivalueObject.getKeys().keySet());
            }
        }

        for (String item : filtered) {

            Path itemPath = PathUtil.appendPath(path, item);

            Resource<ResourceMeta> resource=null;
            if (isDir(item)) {
                resource = loadDir(itemPath);
            } else {
                KeyObject object = this.getVaultObject(itemPath);

                if(rundeckObject){
                    //normal case with rundeck format
                    if(object.isRundeckObject()){
                         resource = loadResource(object,"list");
                    }
                }else{
                    //vault key/value format
                    if(isKeyMultipleValues){
                        //object with multiples keys
                        KeyObject multipleValue= new VaultKey(itemPath, item, multivalueObject.getKeys().get(item));
                        resource = loadResource(multipleValue,"list");
                    }else {
                        if(!object.isRundeckObject()){
                            if (object.isMultiplesKeys()) {
                                resource = loadDir(itemPath);
                            }else {
                                resource = loadResource(object,"list");
                            }
                        }
                    }
                }
            }

            if(resource!=null){
                resources.add(resource);
            }

        }

        return resources;
    }

    @Override
    public boolean hasPath(Path path) {
        try {
            lookup();

            List<String> list = getVaultList(path);
            if(!list.isEmpty()){
                return true;
            }

            KeyObject object = this.getVaultObject(path);
            if(!object.isRundeckObject()&& object.isMultiplesKeys()){
                return true;
            }

            //check if the path is a key
            return hasResource(path);
        } catch (VaultException e) {
            return false;
        }
    }

    @Override
    public boolean hasPath(String path) {
        return hasPath(PathUtil.asPath(path));
    }

    @Override
    public boolean hasResource(Path path) {
        KeyObject object=getVaultObject(path);

        return !object.isError();
    }

    @Override
    public boolean hasResource(String path) {
        return hasResource(PathUtil.asPath(path));
    }

    @Override
    public boolean hasDirectory(Path path) {
        try {
            lookup();

            List<String> list=getVaultList(path);

            if(!list.isEmpty()){
                return true;
            }else{
                KeyObject object = this.getVaultObject(path);
                return !object.isRundeckObject() && object.isMultiplesKeys();
            }

        } catch (VaultException e) {
            return false;
        }
    }

    @Override
    public boolean hasDirectory(String path) {
        return hasDirectory(PathUtil.asPath(path));
    }

    @Override
    public Resource<ResourceMeta> getPath(Path path) {
        if (isVaultDir(path.toString())) {
            return loadDir(path);
        } else {
            return loadResource(path, "read");
        }
    }

    @Override
    public Resource<ResourceMeta> getPath(String path) {
        return getPath(PathUtil.asPath(path));
    }

    @Override
    public Resource<ResourceMeta> getResource(Path path) {
        return loadResource(path, "read");
    }

    @Override
    public Resource<ResourceMeta> getResource(String path) {
        return getResource(PathUtil.asPath(path));
    }

    @Override
    public Set<Resource<ResourceMeta>> listDirectoryResources(Path path) {
        return listResources(path, KeyType.RESOURCE);
    }

    @Override
    public Set<Resource<ResourceMeta>> listDirectoryResources(String path) {
        return listDirectoryResources(PathUtil.asPath(path));
    }

    @Override
    public Set<Resource<ResourceMeta>> listDirectory(Path path) {
        return listResources(path, KeyType.ALL);
    }

    @Override
    public Set<Resource<ResourceMeta>> listDirectory(String path) {
        return listDirectory(PathUtil.asPath(path));
    }

    @Override
    public Set<Resource<ResourceMeta>> listDirectorySubdirs(Path path) {
        return listResources(path, KeyType.DIRECTORY);
    }

    @Override
    public Set<Resource<ResourceMeta>> listDirectorySubdirs(String path) {
        return listDirectoryResources(PathUtil.asPath(path));
    }

    @Override
    public boolean deleteResource(Path path) {
        KeyObject object = this.getVaultObject(path);
        return object.delete(vault,secretBackend,prefix);
    }

    @Override
    public boolean deleteResource(String path) {
        return deleteResource(PathUtil.asPath(path));
    }

    @Override
    public Resource<ResourceMeta> createResource(Path path, ResourceMeta content) {
        saveResource(path, content, "create");
        return loadResource(path, "read");
    }

    @Override
    public Resource<ResourceMeta> createResource(String path, ResourceMeta content) {
        return createResource(PathUtil.asPath(path), content);
    }

    @Override
    public Resource<ResourceMeta> updateResource(Path path, ResourceMeta content) {
        saveResource(path, content, "update");
        return loadResource(path, "read");
    }

    @Override
    public Resource<ResourceMeta> updateResource(String path, ResourceMeta content) {
        return updateResource(PathUtil.asPath(path), content);
    }

    public KeyObject getVaultObject(Path path){
        lookup();

        return KeyObjectBuilder.builder()
                                .path(path)
                                .vault(vault)
                                .vaultPrefix(prefix)
                                .vaultSecretBackend(secretBackend)
                                .build();
    }


    private List<String> getVaultList(Path path) throws VaultException {
        return getVaultList(path.getPath());

    }

    private List<String> getVaultList(String path) throws VaultException {
        LogicalResponse response = vault.list(getVaultPath(path,secretBackend,prefix));
        if (response.getRestResponse().getStatus()==403){
            String body = new String(response.getRestResponse().getBody());
            throw StorageException.listException(
                    PathUtil.asPath(path),
                    String.format("Encountered error while reading data from Vault %s",
                            body));
        }

        return response.getListData();

    }

}
