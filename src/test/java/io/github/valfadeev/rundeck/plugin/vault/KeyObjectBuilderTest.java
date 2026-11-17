package io.github.valfadeev.rundeck.plugin.vault;

import com.dtolabs.rundeck.core.storage.StorageUtil;
import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import org.junit.Test;
import org.rundeck.storage.api.PathUtil;

import java.util.HashMap;
import java.util.Map;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

public class KeyObjectBuilderTest {

    private static KeyObject buildFor(Map<String, String> secretData) throws Exception {
        RestResponse restResponse = mock(RestResponse.class);
        doReturn(200).when(restResponse).getStatus();

        LogicalResponse response = mock(LogicalResponse.class);
        doReturn(secretData).when(response).getData();
        doReturn(restResponse).when(response).getRestResponse();

        Logical vault = mock(Logical.class);
        doReturn(response).when(vault).read(anyString());

        return KeyObjectBuilder.builder()
                .path(PathUtil.asPath("keys/test"))
                .vault(vault)
                .vaultPrefix("rundeck")
                .vaultSecretBackend("secret")
                .build();
    }

    @Test
    public void secretWithRundeckHeadersIsARundeckKey() throws Exception {
        Map<String, String> data = new HashMap<>();
        data.put(VaultStoragePlugin.VAULT_STORAGE_KEY, "s3cret");
        data.put(StorageUtil.RES_META_RUNDECK_CONTENT_TYPE, VaultStoragePlugin.PASSWORD_MIME_TYPE);
        data.put(StorageUtil.RES_META_RUNDECK_CONTENT_LENGTH, "6");

        KeyObject object = buildFor(data);

        assertThat(object, instanceOf(RundeckKey.class));
        assertTrue(object.isRundeckObject());
        assertFalse(object.isError());
    }

    /**
     * A secret written by something other than Rundeck can have a field called "data" without any
     * of the Rundeck headers. It must be handled as a plain Vault secret: reading it as a Rundeck
     * key fails on the missing headers and breaks the listing of the whole directory.
     */
    @Test
    public void foreignSecretWithADataFieldIsNotARundeckKey() throws Exception {
        Map<String, String> data = new HashMap<>();
        data.put(VaultStoragePlugin.VAULT_STORAGE_KEY, "not-a-rundeck-key");
        data.put("owner", "other-team");

        KeyObject object = buildFor(data);

        assertThat(object, instanceOf(VaultKey.class));
        assertFalse(object.isRundeckObject());
        assertFalse(object.isError());
    }
}
