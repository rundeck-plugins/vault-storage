package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.VaultException;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import org.rundeck.storage.api.Path;
import org.rundeck.storage.api.PathUtil;

public class KeyObjectBuilder {

    Path            path;
    Logical         vault;
    String          vaultPrefix;
    String          vaultSecretBackend;

    static KeyObjectBuilder builder() {
        return new KeyObjectBuilder();
    }

    KeyObjectBuilder path(Path path){
        this.path = path;
        return this;
    }

    KeyObjectBuilder vault(Logical vault){
        this.vault = vault;
        return this;
    }

    KeyObjectBuilder vaultPrefix(String vaultPrefix){
        this.vaultPrefix = vaultPrefix;
        return this;
    }

    KeyObjectBuilder vaultSecretBackend(String vaultSecretBackend){
        this.vaultSecretBackend = vaultSecretBackend;
        return this;
    }


    KeyObject build(){
        LogicalResponse response;
        KeyObject object;
        try {
            response = vault.read(VaultStoragePlugin.getVaultPath(path.getPath(),vaultSecretBackend,vaultPrefix));
            String data = response.getData().get(VaultStoragePlugin.VAULT_STORAGE_KEY);

            if(data !=null) {
                object = new RundeckKey(response,path);
            }else{
                object = new VaultKey(response,path);
            }

            if(response.getRestResponse().getStatus()!=200){
                object.error = true;
            }

        } catch (VaultException e) {
            object = new RundeckKey(path);
            object.setErrorMessage(e.getMessage());
            object.setError(true);
        }

        //check if parent path exists (vault entry with multiples keys)
        //multiples keys inside a secret will be reading on Rundeck as different keys inside a folder
        if(object.isError()) {
            KeyObject parentObject=getVaultParentObject(path);

            if(parentObject!=null) {
                object = new VaultKey(path, parentObject);
                Path parentPath = PathUtil.parentPath(path);
                String key = PathUtil.removePrefix(parentPath.toString(), path.toString());

                object.setError(false);
                object.setErrorMessage(null);
                object.setMultiplesKeys(true);

                if (parentObject.getKeys().containsKey(key)) {
                    object.getKeys().put(key, parentObject.getKeys().get(key));
                }
            }
        }

        return object;
    }

    public KeyObject getVaultParentObject(Path path){
        KeyObject parentObject=null;
        LogicalResponse response;

        Path parentPath = PathUtil.parentPath(path);
        try {
            response = vault.read(VaultStoragePlugin.getVaultPath(parentPath.getPath(),vaultSecretBackend,vaultPrefix));

            if(response.getRestResponse().getStatus()!=200){
                return null;
            }

            parentObject=new VaultKey(response, parentPath);
        } catch (VaultException e) {

        }

        return parentObject;
    }
}
