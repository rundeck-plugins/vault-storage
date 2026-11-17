package io.github.valfadeev.rundeck.plugin.vault;

import io.github.jopenlibs.vault.api.Logical;
import io.github.jopenlibs.vault.response.LogicalResponse;
import io.github.jopenlibs.vault.rest.RestResponse;
import org.junit.Test;
import org.rundeck.storage.api.PathUtil;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

/**
 * A path that cannot be read directly may still be a field of a multi-key Vault secret stored at
 * its parent path. It must only resolve that way when the parent really has that field.
 */
public class KeyObjectBuilderParentLookupTest {

    private static LogicalResponse response(int status, Map<String, String> data) {
        RestResponse restResponse = mock(RestResponse.class);
        doReturn(status).when(restResponse).getStatus();

        LogicalResponse response = mock(LogicalResponse.class);
        doReturn(data).when(response).getData();
        doReturn(restResponse).when(response).getRestResponse();
        return response;
    }

    /** Vault holds one multi-key secret at keys/app with the fields "user" and "password". */
    private static KeyObject buildFor(String path) throws Exception {
        Map<String, String> parentData = new HashMap<>();
        parentData.put("user", "admin");
        parentData.put("password", "s3cret");

        Logical vault = mock(Logical.class);
        doReturn(response(200, parentData)).when(vault).read("secret/rundeck/keys/app");
        doReturn(response(404, Collections.emptyMap())).when(vault).read("secret/rundeck/" + path);

        return KeyObjectBuilder.builder()
                .path(PathUtil.asPath(path))
                .vault(vault)
                .vaultPrefix("rundeck")
                .vaultSecretBackend("secret")
                .build();
    }

    @Test
    public void fieldOfAMultiKeyParentResolves() throws Exception {
        KeyObject object = buildFor("keys/app/password");

        assertFalse(object.isError());
        assertTrue(object.isMultiplesKeys());
        assertEquals("s3cret", object.getKeys().get("password"));
    }

    @Test
    public void pathThatIsNotAFieldOfItsParentStaysAnError() throws Exception {
        KeyObject object = buildFor("keys/app/missing");

        assertTrue("a path that exists neither as a secret nor as a field of its parent must not resolve",
                object.isError());
    }
}
