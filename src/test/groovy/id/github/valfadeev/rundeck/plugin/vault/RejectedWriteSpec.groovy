package id.github.valfadeev.rundeck.plugin.vault

import io.github.jopenlibs.vault.Vault
import io.github.jopenlibs.vault.api.Auth
import io.github.jopenlibs.vault.api.Logical
import io.github.jopenlibs.vault.response.LogicalResponse
import io.github.jopenlibs.vault.response.LookupResponse
import io.github.jopenlibs.vault.rest.RestResponse
import io.github.valfadeev.rundeck.plugin.vault.VaultStoragePlugin
import com.dtolabs.rundeck.core.storage.ResourceMeta
import org.rundeck.storage.api.StorageException
import spock.lang.Specification

class RejectedWriteSpec extends Specification {

    def "create fails when vault rejects the write with a 4xx status"() {
        given:
        Properties properties = ["address":"http://localhost:8200",
                                 "maxRetries":"1",
                                 "retryIntervalMilliseconds":"200",
                                 "engineVersion":"2",
                                 "openTimeout":"20",
                                 "readTimeout":"20",
                                 "authBackend":"token",
                                 "token":"123456"]
        def plugin = new VaultStoragePlugin()
        plugin.properties = properties

        // The driver returns 4xx responses from write() instead of throwing
        Logical vault = Mock(Logical) {
            write(_, _) >> Mock(LogicalResponse) {
                getRestResponse() >> Mock(RestResponse) {
                    getStatus() >> 403
                    getBody() >> '{"errors":["permission denied"]}'.bytes
                }
            }
        }

        Vault vaultClient = Mock(Vault) {
            auth() >> Mock(Auth) {
                lookupSelf() >> Mock(LookupResponse) {
                    getTTL() >> 120
                }
            }
        }

        plugin.vault = vault
        plugin.vaultClient = vaultClient

        ResourceMeta content = Mock(ResourceMeta) {
            getMeta() >> ["Rundeck-content-type": "application/x-rundeck-data-password"]
            writeContent(_) >> { OutputStream out -> out.write("secret".bytes); 6L }
        }

        when:
        plugin.createResource("keys/test/password", content)

        then:
        def e = thrown(StorageException)
        e.message.contains("403")
        e.message.contains("permission denied")
    }

}
