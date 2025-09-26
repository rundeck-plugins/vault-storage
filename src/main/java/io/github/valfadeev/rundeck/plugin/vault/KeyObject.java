package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.api.Logical;
import com.dtolabs.rundeck.core.storage.ResourceMeta;
import org.rundeck.storage.api.Path;
import org.rundeck.storage.impl.ResourceBase;

import java.io.ByteArrayOutputStream;
import java.util.Map;

public abstract class KeyObject {

    protected boolean             rundeckObject;
    protected boolean             multiplesKeys;
    protected Map<String, String> payload;
    protected Map<String, Object> keys;
    protected Path                path;

    protected boolean             error;
    protected String              errorMessage;

    abstract Map<String, Object> saveResource(ResourceMeta content, String event, ByteArrayOutputStream baoStream);
    abstract ResourceBase loadResource();
    abstract boolean delete(Logical vault,String vaultSecretBackend ,String vaultPrefix);

    //empty object or null object
    public KeyObject(Path path) {
        this.path=path;
    }

    public boolean isRundeckObject() {
        return rundeckObject;
    }

    public void setRundeckObject(final boolean rundeckObject) {
        this.rundeckObject = rundeckObject;
    }

    public boolean isMultiplesKeys() {
        return multiplesKeys;
    }

    public void setMultiplesKeys(final boolean multiplesKeys) {
        this.multiplesKeys = multiplesKeys;
    }

    public Map<String, String> getPayload() {
        return payload;
    }

    public void setPayload(final Map<String, String> payload) {
        this.payload = payload;
    }

    public Map<String, Object> getKeys() {
        return keys;
    }

    public void setKeys(final Map<String, Object> keys) {
        this.keys = keys;
    }

    public Path getPath() {
        return path;
    }

    public void setPath(final Path path) {
        this.path = path;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(final String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public boolean isError() {
        return error;
    }

    public void setError(final boolean error) {
        this.error = error;
    }

    @Override
    public String toString() {
        return "KeyObject{" +
               "rundeckObject=" + rundeckObject +
               ", multiplesKeys=" + multiplesKeys +
               ", payload=" + payload +
               ", keys=" + keys +
               ", path=" + path +
               ", error=" + error +
               ", errorMessage='" + errorMessage + '\'' +
               '}';
    }
}
