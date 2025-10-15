package id.github.valfadeev.rundeck.plugin.vault

import io.github.jopenlibs.vault.Vault
import io.github.jopenlibs.vault.VaultConfig
import io.github.jopenlibs.vault.api.Auth
import io.github.jopenlibs.vault.api.Logical
import io.github.jopenlibs.vault.response.LogicalResponse
import io.github.jopenlibs.vault.response.LookupResponse
import io.github.jopenlibs.vault.rest.RestResponse
import io.github.jopenlibs.vault.response.AuthResponse
import io.github.valfadeev.rundeck.plugin.vault.VaultStoragePlugin
import spock.lang.Specification

class VaultStoragePluginSpec extends Specification{

    def "trigger error when vault returns with permission deny"(){
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
        plugin.properties=properties;

        Logical vault = Mock(Logical){
            list(_)>>Mock(LogicalResponse){
                getRestResponse()>>Mock(RestResponse){
                    getStatus()>> 403
                }
            }
        }

        Vault vaultClient = Mock(Vault){
            auth()>>Mock(Auth){
                lookupSelf()>>Mock(LookupResponse){
                    getTTL()>>120
                }
            }
        }

        plugin.vault = vault
        plugin.vaultClient = vaultClient

        when:
        def result = plugin.hasDirectory("keys/test")

        then:
        thrown Exception

    }


    def "has directories keys"(){
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
        plugin.properties=properties;

        Logical vault = Mock(Logical){
            list(_)>>Mock(LogicalResponse){
                getRestResponse()>>Mock(RestResponse){
                    getStatus()>> 200

                }
                getListData()>>["key1","key2"]
            }
        }

        Vault vaultClient = Mock(Vault){
            auth()>>Mock(Auth){
                lookupSelf()>>Mock(LookupResponse){
                    getTTL()>>120
                }
            }
        }

        plugin.vault = vault
        plugin.vaultClient = vaultClient

        when:
        def result = plugin.hasDirectory("keys/test")

        then:
        result

    }
    def "cert auth: plugin calls loginByCert then throws on 403 list"() {
        given:
        def props = [
                address                   : "http://localhost:8200",
                maxRetries                : "1",
                retryIntervalMilliseconds : "200",
                engineVersion             : "2",
                openTimeout               : "20",
                readTimeout               : "20",
                authBackend               : "cert" // force cert path
        ]
        def plugin = new VaultStoragePlugin()
        plugin.properties = props

        // Build the mocks the plugin will use once Vault.create(...) is called
        def authApi     = Mock(Auth)
        def logicalApi  = Mock(Logical)
        def vaultClient = Mock(Vault) {
            auth()    >> authApi
            logical() >> logicalApi
        }

        // monkey-patch factory to return our mock Vault client
        def registry = GroovySystem.metaClassRegistry
        def oldMc = registry.getMetaClass(Vault)
        Vault.metaClass.'static'.create = { VaultConfig cfg -> vaultClient }

        // Drive interactions
        authApi.lookupSelf() >> { throw new RuntimeException("no token") } // force loginByCert
        def authResp = Mock(AuthResponse) {
            getAuthClientToken() >> "s.certtoken"
            getRestResponse() >> Mock(RestResponse) { getStatus() >> 200; getBody() >> "{}" }
        }
        authApi.loginByCert() >> authResp

        def listResp = Mock(LogicalResponse) {
            getRestResponse() >> Mock(RestResponse) { getStatus() >> 403; getBody() >> "permission denied" }
        }
        logicalApi.list(_ as String) >> listResp

        when:
        plugin.hasDirectory("keys/test")

        then:
        thrown(Exception)

        cleanup:
        // Restore original metaclass
        registry.setMetaClass(Vault, oldMc)
    }

    def "cert auth: lists directory successfully with getVaultList"() {
        given:
        Properties properties = [
                address                  : "https://localhost:8202",
                maxRetries               : "1",
                retryIntervalMilliseconds: "200",
                engineVersion            : "2",
                openTimeout              : "20",
                readTimeout              : "20",
                authBackend              : "cert",
                certificate              : "/path/to/client.pem",
                truststore               : "/path/to/ca.pem",
                // props used by getVaultList path building
                secretBackend            : "secret",
                prefix                   : "app",
                pathBehaviour            : "predefined",
                storageBehaviour         : "vault"
        ]
        def plugin = new VaultStoragePlugin()
        plugin.properties = properties

        // getVaultList() expects KV v2 LIST shape: {"data":{"keys":[...]}}
        def logicalResponse = Mock(LogicalResponse) {
            getRestResponse() >> Mock(RestResponse) {
                getStatus() >> 200
                getBody()  >> '{"data":{"keys":["key1","key2"]}}'.bytes
            }
            getListData() >> ["key1", "key2"]
        }

        Logical logical = Mock(Logical) {
            1 * list(_ as String) >> logicalResponse
        }

        def authApi = Mock(Auth)
        Vault vaultClient = Mock(Vault) {
            auth() >> authApi
            logical() >> logical
        }

        // The plugin may first do lookupSelf() and only call loginByCert() if needed.
        // So allow 0..1 login calls but ensure lookupSelf() returns a healthy token.
        (0..1) * authApi.loginByCert() >> Mock(AuthResponse) {
            getAuthClientToken() >> "s.certtoken"
        }
        1 * authApi.lookupSelf() >> Mock(LookupResponse) {
            getNumUses() >> 10
            getTTL() >> 120
        }

        plugin.vault = logical
        plugin.vaultClient = vaultClient

        when:
        def result = plugin.hasDirectory("keys/test")

        then:
        result
    }


    def "cert auth: re-login when token considered expired then succeed (getVaultList)"() {
        given:
        Properties properties = [
                address                  : "https://localhost:8202",
                maxRetries               : "1",
                retryIntervalMilliseconds: "200",
                engineVersion            : "2",
                openTimeout              : "20",
                readTimeout              : "20",
                authBackend              : "cert",
                certificate              : "/path/to/client.pem",
                truststore               : "/path/to/ca.pem",
                secretBackend            : "secret",
                prefix                   : "app",
                pathBehaviour            : "predefined",
                storageBehaviour         : "vault"
        ]
        def plugin = new VaultStoragePlugin()
        plugin.properties = properties

        def logicalResponse = Mock(LogicalResponse) {
            getRestResponse() >> Mock(RestResponse) {
                getStatus() >> 200
                getBody()  >> '{"data":{"keys":["ok"]}}'.bytes
            }
            getListData() >> ["ok"]
        }

        Logical logical = Mock(Logical) {
            1 * list(_ as String) >> logicalResponse
        }

        def authApi = Mock(Auth)
        Vault vaultClient = Mock(Vault) {
            auth() >> authApi
            logical() >> logical
        }

        // The plugin may first do lookupSelf() and only call loginByCert() if needed.
        // Permit 0..1 initial logins and any additional (e.g., refresh) logins.
        (0.._) * authApi.loginByCert() >> Mock(AuthResponse) {
            getAuthClientToken() >> "s.token"
        }

        // Ordered interactions: first lookupSelf reports an expired token,
        // any subsequent lookupSelf calls report a healthy token.
        1 * authApi.lookupSelf() >> Mock(LookupResponse) {
            getNumUses() >> 0
            getTTL()     >> 0
        }
        (0.._) * authApi.lookupSelf() >> Mock(LookupResponse) {
            getNumUses() >> 10
            getTTL()     >> 120
        }

        plugin.vault = logical
        plugin.vaultClient = vaultClient

        expect:
        plugin.hasDirectory("keys/test")
    }
    def "cert auth: missing certificate fails fast and does not call loginByCert"() {
        given:
        def props = [
                address: "https://localhost:8202",
                authBackend: "cert",
                certificate: "",             // missing
                truststore: "/path/to/ca.pem"
        ]
        def plugin = new VaultStoragePlugin(properties: props)

        def authApi = Mock(Auth)
        def vaultClient = Mock(Vault) { auth() >> authApi }

        // monkey-patch factory
        def reg = GroovySystem.metaClassRegistry
        def oldMc = reg.getMetaClass(Vault)
        Vault.metaClass.'static'.create = { VaultConfig cfg -> vaultClient }

        when:
        plugin.hasDirectory("keys/test")

        then:
        thrown(Exception)
        0 * authApi.loginByCert()       // never tries to hit Vault

        cleanup:
        reg.setMetaClass(Vault, oldMc)
    }

    def "cert auth: list empty -> hasDirectory returns true (kv2 empty dir)"() {
        given:
        def props = [
                address: "https://localhost:8202",
                engineVersion: "2",
                authBackend: "cert",
                certificate: "/path/to/client.pem",
                truststore: "/path/to/ca.pem",
                secretBackend: "secret",
                prefix: "app",
                pathBehaviour: "predefined",
                storageBehaviour: "vault",
                maxRetries: "1",
                readTimeout: "20",
                openTimeout: "20",
                retryIntervalMilliseconds: "200",
        ]
        def plugin = new VaultStoragePlugin(properties: props)

        def authApi    = Mock(Auth)
        def logicalApi = Mock(Logical)
        def vaultClient = Mock(Vault) { auth() >> authApi; logical() >> logicalApi }

        (0.._) * authApi.loginByCert() >> Mock(AuthResponse) {
            getAuthClientToken() >> "s.certtoken"
            getRestResponse() >> Mock(RestResponse) { getStatus() >> 200; getBody() >> "{}" }
        }
        (1.._) * authApi.lookupSelf() >> Mock(LookupResponse) { getNumUses() >> 10; getTTL() >> 120 }

        // LIST returns empty array (dir exists but empty)
        def listResp = Mock(LogicalResponse) {
            getRestResponse() >> Mock(RestResponse) { getStatus() >> 200; getBody() >> '{"data":{"keys":[]}}' }
            getListData() >> []
        }
        1 * logicalApi.list(_ as String) >> listResp

        // Plugin may do a READ to build a key object; feed minimal non-null data
        def readResp = Mock(LogicalResponse) {
            getRestResponse() >> Mock(RestResponse) { getStatus() >> 200; getBody() >> '{"data":{"name":"missing","type":"dir"}}' }
            getData() >> [name: "missing", type: "dir"]
        }
        (0..1) * logicalApi.read(_ as String) >> readResp
        // monkey-patch factory
        def reg = GroovySystem.metaClassRegistry
        def oldMc = reg.getMetaClass(Vault)
        Vault.metaClass.'static'.create = { VaultConfig cfg -> vaultClient }
        plugin.vault = logicalApi
        plugin.vaultClient = vaultClient

        expect:
        plugin.hasDirectory("keys/missing")   // now expecting true

        cleanup:
        reg.setMetaClass(Vault, oldMc)
    }





}
