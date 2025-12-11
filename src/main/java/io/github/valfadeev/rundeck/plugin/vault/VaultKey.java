package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import com.dtolabs.rundeck.core.storage.ResourceMeta;
import com.dtolabs.rundeck.core.storage.ResourceMetaBuilder;
import com.dtolabs.rundeck.core.storage.StorageUtil;
import org.rundeck.storage.api.Path;
import org.rundeck.storage.api.PathUtil;
import org.rundeck.storage.api.StorageException;
import org.rundeck.storage.impl.ResourceBase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VaultKey extends KeyObject {

    private static final Logger LOG = LoggerFactory.getLogger(VaultKey.class);

    KeyObject parent;

    public VaultKey(LogicalResponse response, Path path) {
        super(path);

        this.payload = response.getData();
        this.path = path;
        this.keys = new HashMap<>();

        for (Map.Entry<String, String> entry : payload.entrySet()) {
            this.keys.put(entry.getKey(),entry.getValue());
        }

        this.rundeckObject=false;
        if(keys.size()>1){
            this.multiplesKeys=true;
        }else{
            this.multiplesKeys=false;
        }

    }

    public VaultKey(final Path path, KeyObject parent ) {
        super(path);
        this.parent=parent;
        this.keys = new HashMap<>();
    }

    public VaultKey(final Path path, final String item, final Object value) {
        super(path);
        this.keys = new HashMap<>();
        keys.put(item,value);

    }

    public Map<String, Object> saveResource(ResourceMeta content, String event, ByteArrayOutputStream baoStream){

        Path path=this.getPath();
        Map<String, Object> payload = new HashMap<>();

        //just saving key/value format
        if (event.equals("update")) {

            if(this.isMultiplesKeys()){
                //if the vault object has multiples key/values, update single value here
                //what we are going to save is the parent value
                Path parentPath = PathUtil.parentPath(this.getPath());
                String key = PathUtil.removePrefix(parentPath.toString(), this.getPath().toString());

                this.path = parentPath;

                try {
                    String data = baoStream.toString("UTF-8");

                    payload.putAll(parent.getKeys());
                    if(payload.containsKey(key)){
                        payload.replace(key,data);
                    }else{
                        payload.put(key,data);
                    }

                } catch (UnsupportedEncodingException e) {
                    throw new StorageException(
                            String.format(
                                    "Encountered unsupported encoding error: %s",
                                    e.getMessage()
                            ),
                            StorageException.Event.valueOf(event.toUpperCase()),
                            path
                    );
                }
            }else{
                //if it has a single value
                try {
                    String data = baoStream.toString("UTF-8");
                    for (Map.Entry<String, Object> entry : this.getKeys().entrySet()) {
                        payload.put(entry.getKey(),data);
                    }

                } catch (UnsupportedEncodingException e) {
                    throw new StorageException(
                            String.format(
                                    "Encountered unsupported encoding error: %s",
                                    e.getMessage()
                            ),
                            StorageException.Event.valueOf(event.toUpperCase()),
                            path
                    );
                }
            }
        }else{
            try {
                String data = baoStream.toString("UTF-8");
                payload.put("value", data);
            } catch (UnsupportedEncodingException e) {
                throw new StorageException(
                        String.format(
                                "Encountered unsupported encoding error: %s",
                                e.getMessage()
                        ),
                        StorageException.Event.valueOf(event.toUpperCase()),
                        path
                );
            }
        }

        return payload;
    }


    ResourceBase loadResource(){
        for (Map.Entry<String, Object> entry : this.getKeys().entrySet())
        {
            String value = entry.getValue().toString();

            ResourceMetaBuilder builder = new ResourceMetaBuilder();
            builder.setContentLength(value.length());

            if(value.contains("-----BEGIN RSA PRIVATE KEY-----") || value.contains(System.getProperty("line.separator"))){
                builder.setContentType(VaultStoragePlugin.PRIVATE_KEY_MIME_TYPE);
                builder.setMeta(VaultStoragePlugin.RUNDECK_CONTENT_MASK, "content");
                builder.setMeta(VaultStoragePlugin.RUNDECK_KEY_TYPE, "private");
            }
            else{
                builder.setContentType(VaultStoragePlugin.PASSWORD_MIME_TYPE);
                builder.setMeta(VaultStoragePlugin.RUNDECK_CONTENT_MASK, "content");
                builder.setMeta(VaultStoragePlugin.RUNDECK_DATA_TYPE, "password");
            }

            // Parse and set timestamps from Vault metadata (KV v2)
            if (this.vaultMetadata != null && !this.vaultMetadata.isEmpty()) {
                String createdTime = this.vaultMetadata.get("created_time");
                String updatedTime = this.vaultMetadata.get("updated_time");

                // Parse creation time
                if (createdTime != null && createdTime.length() >= 19) {
                    try {
                        // Vault returns timestamps in RFC3339 format (ISO 8601) in UTC
                        // Example: "2025-03-13T16:25:00.123456Z"
                        SimpleDateFormat vaultDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.ENGLISH);
                        vaultDateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
                        Date creationDate = vaultDateFormat.parse(createdTime.substring(0, 19));

                        builder.setCreationTime(creationDate);

                        // Use updated_time for modification time if available, otherwise use created_time
                        if (updatedTime != null && updatedTime.length() >= 19) {
                            try {
                                Date modificationDate = vaultDateFormat.parse(updatedTime.substring(0, 19));
                                builder.setModificationTime(modificationDate);
                            } catch (ParseException e) {
                                LOG.warn("Failed to parse Vault updated_time '{}', falling back to created_time", updatedTime, e);
                                builder.setModificationTime(creationDate);
                            }
                        } else {
                            builder.setModificationTime(creationDate);
                        }
                    } catch (ParseException e) {
                        LOG.warn("Failed to parse Vault created_time '{}', timestamps will not be set", createdTime, e);
                    }
                }
            }

            ByteArrayInputStream baiStream = new ByteArrayInputStream(value.getBytes());

            return new ResourceBase<>(
                    this.getPath(),
                    StorageUtil.withStream(baiStream, builder.getResourceMeta()),
                    false
            );

        }

        return null;
    }

    @Override
    boolean delete(final Logical vault,String vaultSecretBackend, String vaultPrefix) {
        String event="delete";

        if(this.parent!=null){
            //remove just a key inside a parent
            Path parentPath = PathUtil.parentPath(this.path);
            String key = PathUtil.removePrefix(parentPath.toString(), this.path.toString());
            this.parent.getKeys().remove(key);

            try {
                vault.write(VaultStoragePlugin.getVaultPath(this.parent.getPath().getPath(),vaultSecretBackend, vaultPrefix), this.parent.getKeys());
                return true;
            } catch (VaultException e) {
                throw new StorageException(
                        String.format("Encountered error while writing data to Vault %s",
                                      e.getMessage()),
                        StorageException.Event.valueOf(event.toUpperCase()),
                        path);
            }

        }else{
            try {
                vault.delete(VaultStoragePlugin.getVaultPath(path.getPath(),vaultSecretBackend, vaultPrefix));
                return true;
            } catch (VaultException e) {
                return false;
            }
        }
    }
}
