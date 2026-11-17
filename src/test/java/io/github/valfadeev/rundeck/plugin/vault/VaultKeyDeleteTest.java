package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.rundeck.storage.api.PathUtil;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Deleting one field of a multi-key Vault secret rewrites the parent secret without that field.
 */
public class VaultKeyDeleteTest {

    /** A key for the field "password" of the secret keys/app, which holds "user" and "password". */
    private static VaultKey fieldOfMultiKeySecret() {
        Map<String, String> parentData = new HashMap<>();
        parentData.put("user", "admin");
        parentData.put("password", "s3cret");
        LogicalResponse parentResponse = mock(LogicalResponse.class);
        doReturn(parentData).when(parentResponse).getData();

        VaultKey parent = new VaultKey(parentResponse, PathUtil.asPath("keys/app"));
        return new VaultKey(PathUtil.asPath("keys/app/password"), parent);
    }

    private static Logical vaultAnsweringWritesWith(int status) throws Exception {
        RestResponse restResponse = mock(RestResponse.class);
        doReturn(status).when(restResponse).getStatus();
        LogicalResponse response = mock(LogicalResponse.class);
        doReturn(restResponse).when(response).getRestResponse();

        Logical vault = mock(Logical.class);
        doReturn(response).when(vault).write(anyString(), anyMap());
        return vault;
    }

    @Test
    public void deletingAFieldRewritesTheParentWithoutIt() throws Exception {
        Logical vault = vaultAnsweringWritesWith(204);

        boolean deleted = fieldOfMultiKeySecret().delete(vault, "secret", "rundeck");

        assertTrue(deleted);
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, Object>> written = ArgumentCaptor.forClass(Map.class);
        verify(vault).write(eq("secret/rundeck/keys/app"), written.capture());
        Map<String, Object> expected = new HashMap<>();
        expected.put("user", "admin");
        assertEquals("sibling fields must be kept, the deleted one removed", expected, written.getValue());
    }

    @Test
    public void deletingAFieldSucceedsOnA200Response() throws Exception {
        assertTrue(fieldOfMultiKeySecret().delete(vaultAnsweringWritesWith(200), "secret", "rundeck"));
    }

    /** The driver returns 4xx responses instead of throwing: nothing was deleted. */
    @Test
    public void deletingAFieldFailsWhenVaultRejectsTheParentRewrite() throws Exception {
        assertFalse(fieldOfMultiKeySecret().delete(vaultAnsweringWritesWith(403), "secret", "rundeck"));
    }
}
