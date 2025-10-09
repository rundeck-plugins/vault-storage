package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import com.dtolabs.rundeck.core.storage.ResourceMeta;
import com.dtolabs.rundeck.core.storage.ResourceMetaBuilder;
import com.dtolabs.rundeck.core.storage.StorageUtil;
import org.rundeck.storage.api.Path;
import org.rundeck.storage.api.Resource;
import org.rundeck.storage.api.StorageException;
import org.rundeck.storage.impl.ResourceBase;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class RundeckKey extends KeyObject {

    public RundeckKey(LogicalResponse response, Path path) {
        super(path);
        this.payload = response.getData();
        this.path = path;
        this.rundeckObject=true;
        this.multiplesKeys=false;
    }

    public RundeckKey(final Path path) {
        super(path);
    }

    public Map<String, Object> saveResource(ResourceMeta content, String event, ByteArrayOutputStream baoStream){

        Map<String, Object> payload = new HashMap<>();

        Map<String, String> meta = content.getMeta();

        for (String k : meta.keySet()) {
            payload.put(k, meta.get(k));
        }

        if (event.equals("update")) {
            DateFormat df = new SimpleDateFormat(StorageUtil.ISO_8601_FORMAT, Locale.ENGLISH);
            Resource<ResourceMeta> existing = this.loadResource();
            payload.put(
                    StorageUtil.RES_META_RUNDECK_CONTENT_CREATION_TIME,
                    df.format(existing.getContents().getCreationTime())
            );
        }

        try {
            String data = baoStream.toString("UTF-8");
            payload.put(VaultStoragePlugin.VAULT_STORAGE_KEY, data);
        } catch (UnsupportedEncodingException e) {
            throw new StorageException(
                    String.format(
                            "Encountered unsupported encoding error: %s",
                            e.getMessage()
                    ),
                    StorageException.Event.valueOf(event.toUpperCase()),
                    this.getPath()
            );
        }

        return payload;
    }

    ResourceBase loadResource(){
        Map<String, String> payload = this.getPayload();
        String data = payload.get(VaultStoragePlugin.VAULT_STORAGE_KEY);

        ResourceMetaBuilder builder = new ResourceMetaBuilder();
        builder.setContentLength(Long.parseLong(payload.get(StorageUtil.RES_META_RUNDECK_CONTENT_LENGTH)));
        builder.setContentType(payload.get(StorageUtil.RES_META_RUNDECK_CONTENT_TYPE));

        DateFormat df = new SimpleDateFormat(StorageUtil.ISO_8601_FORMAT, Locale.ENGLISH);
        try {
            builder.setCreationTime(df.parse(payload.get(StorageUtil.RES_META_RUNDECK_CONTENT_CREATION_TIME)));
            builder.setModificationTime(df.parse(payload.get(StorageUtil.RES_META_RUNDECK_CONTENT_MODIFY_TIME)));
        } catch (ParseException e) {
        }

        String type = payload.get(StorageUtil.RES_META_RUNDECK_CONTENT_TYPE);
        if (type.equals(VaultStoragePlugin.PRIVATE_KEY_MIME_TYPE)) {
            builder.setMeta(VaultStoragePlugin.RUNDECK_CONTENT_MASK, "content");
            builder.setMeta(VaultStoragePlugin.RUNDECK_KEY_TYPE, "private");
        }
        else if (type.equals(VaultStoragePlugin.PUBLIC_KEY_MIME_TYPE)) {
            builder.setMeta(VaultStoragePlugin.RUNDECK_KEY_TYPE, "public");
        }
        else if (type.equals(VaultStoragePlugin.PASSWORD_MIME_TYPE)) {
            builder.setMeta(VaultStoragePlugin.RUNDECK_CONTENT_MASK, "content");
            builder.setMeta(VaultStoragePlugin.RUNDECK_DATA_TYPE, "password");
        }

        ByteArrayInputStream baiStream = new ByteArrayInputStream(data.getBytes());
        return new ResourceBase<>(
                this.getPath(),
                StorageUtil.withStream(baiStream, builder.getResourceMeta()),
                false
        );
    }

    @Override
    boolean delete(final Logical vault,String vaultSecretBackend, String vaultPrefix) {

        try {
            vault.delete(VaultStoragePlugin.getVaultPath(path.getPath(), vaultSecretBackend, vaultPrefix));
            return true;
        } catch (VaultException e) {
            return false;
        }

    }
}
