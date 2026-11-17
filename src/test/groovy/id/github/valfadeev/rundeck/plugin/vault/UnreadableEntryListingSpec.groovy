package id.github.valfadeev.rundeck.plugin.vault

import io.github.jopenlibs.vault.Vault
import io.github.jopenlibs.vault.api.Auth
import io.github.jopenlibs.vault.api.Logical
import io.github.jopenlibs.vault.response.LogicalResponse
import io.github.jopenlibs.vault.response.LookupResponse
import io.github.jopenlibs.vault.rest.RestResponse
import io.github.valfadeev.rundeck.plugin.vault.VaultStoragePlugin
import spock.lang.Specification

class UnreadableEntryListingSpec extends Specification {

    def "vault mode: an entry that is listed but cannot be read does not fail the listing"() {
        given:
        Properties properties = ["address":"http://localhost:8200",
                                 "maxRetries":"1",
                                 "retryIntervalMilliseconds":"200",
                                 "engineVersion":"2",
                                 "openTimeout":"20",
                                 "readTimeout":"20",
                                 "authBackend":"token",
                                 "storageBehaviour":"vault",
                                 "token":"123456"]
        def plugin = new VaultStoragePlugin()
        plugin.properties = properties
        plugin.rundeckObject = false

        def readable = Mock(LogicalResponse) {
            getRestResponse() >> Mock(RestResponse) { getStatus() >> 200 }
            getData() >> [value: "s3cret"]
        }
        // e.g. a KV v2 secret whose latest version was soft-deleted: still listed, read gives 404
        def unreadable = Mock(LogicalResponse) {
            getRestResponse() >> Mock(RestResponse) { getStatus() >> 404 }
            getData() >> [:]
        }

        Logical vault = Mock(Logical) {
            list(_) >> Mock(LogicalResponse) {
                getRestResponse() >> Mock(RestResponse) { getStatus() >> 200 }
                getListData() >> ["ok", "gone"]
            }
            read(_) >> { String vaultPath -> vaultPath.endsWith("/ok") ? readable : unreadable }
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
        def result = plugin.listDirectory("keys/test")

        then:
        result.collect { it.path.path } == ["keys/test/ok"]
    }

}
