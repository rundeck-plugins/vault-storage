package id.github.valfadeev.rundeck.plugin.vault

import io.github.jopenlibs.vault.Vault
import io.github.jopenlibs.vault.api.Auth
import io.github.jopenlibs.vault.api.Logical
import io.github.jopenlibs.vault.response.LogicalResponse
import io.github.jopenlibs.vault.response.LookupResponse
import io.github.jopenlibs.vault.rest.RestResponse
import io.github.valfadeev.rundeck.plugin.vault.VaultStoragePlugin
import spock.lang.Specification

class ListDirectorySubdirsSpec extends Specification {

    def "listDirectorySubdirs with a String path returns only subdirectories"() {
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

        Logical vault = Mock(Logical) {
            list(_) >> Mock(LogicalResponse) {
                getRestResponse() >> Mock(RestResponse) {
                    getStatus() >> 200
                }
                getListData() >> ["akey", "sub/"]
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

        when:
        def result = plugin.listDirectorySubdirs("keys/test")

        then:
        result.size() == 1
        result.every { it.directory }
        result.collect { it.path.path } == ["keys/test/sub"]
    }

}
