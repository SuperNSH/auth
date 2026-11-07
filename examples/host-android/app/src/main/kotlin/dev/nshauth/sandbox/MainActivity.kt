package dev.nshauth.sandbox

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.util.Log
import com.longbridge.nsh.NshView
import dev.nshauth.sandbox.auth.AuthHostModule

/**
 * Embeds the nsh-auth demo bundle (assets/nsh) and answers its host channel:
 * Custom Tabs authorize, Keystore-backed secure storage and launch config.
 * The provider redirect returns through the nsh.auth.sandbox://callback intent
 * filter and completes the pending auth.authorize with {callbackUrl}.
 */
class MainActivity : Activity() {

    private lateinit var nsh: NshView
    private lateinit var auth: AuthHostModule

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        auth = AuthHostModule(this)
        auth.handleLaunchIntent(intent) // the launcher's extras; a redirect can cold-start us
        nsh = NshView(this)
        nsh.setErrorListener { Log.e(TAG, it) }
        setContentView(nsh)
        // host.params is read synchronously at load, so set it before the bundle:
        // the host is the source of truth for the redirect URI.
        check(nsh.setParams(auth.paramsReply())) { "invalid launch params" }
        // The same names the demo's nsh.json declares; the host grant caps them.
        check(nsh.setGrantedCapabilities(HOST_GRANT)) { "invalid capability grant" }
        installAuthHandlers()
        check(nsh.loadAssetBundle("nsh")) { "cannot read assets/nsh - run examples/host-android/build-gate.sh" }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        auth.handleRedirectIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        // An authorize that came back without a redirect (browser backed out) is cancelled.
        auth.onHostResumed()
    }

    override fun onDestroy() {
        auth.onHostDestroyed()
        nsh.destroy()
        super.onDestroy()
    }

    private fun installAuthHandlers() {
        nsh.handle("auth.config") { _, reply ->
            reply.resolve(auth.configReply())
        }
        nsh.handle("auth.authorize") { data, reply ->
            val url = requireString(data, "url", "auth.authorize")
            val scheme = requireString(data, "scheme", "auth.authorize")
            // Optional resumption metadata for the process-death record; the core
            // owns PKCE and passes what it wants parked in the secure store.
            val verifier = optionalString(data, "verifier")
            val state = optionalString(data, "state")
            val provider = optionalString(data, "provider")
            auth.authorize(url, scheme, verifier, state, provider) { result ->
                result.fold(
                    onSuccess = { reply.resolve(mapOf("callbackUrl" to it)) },
                    onFailure = { reply.reject(it.message ?: "error") },
                )
            }
        }
        nsh.handle("auth.pendingAuthorize") { data, reply ->
            // Without args: report (and keep) any flow parked by a process death.
            // {clear: true}: the app consumed it, drop the record.
            val clear = (data as? Map<*, *>)?.get("clear") as? Boolean == true
            auth.pendingAuthorize(clear) { record ->
                reply.resolve(record)
            }
        }
        nsh.handle("auth.store.save") { data, reply ->
            val key = requireString(data, "key", "auth.store.save")
            val value = requireString(data, "value", "auth.store.save")
            auth.storeSave(key, value) { result ->
                result.fold(
                    onSuccess = { reply.resolve(emptyMap<String, String>()) },
                    onFailure = { reply.reject(it.message ?: "error") },
                )
            }
        }
        nsh.handle("auth.store.load") { data, reply ->
            val key = requireString(data, "key", "auth.store.load")
            auth.storeLoad(key) { result ->
                result.fold(
                    onSuccess = { reply.resolve(mapOf("value" to it)) },
                    onFailure = { reply.reject(it.message ?: "error") },
                )
            }
        }
        nsh.handle("auth.store.clear") { data, reply ->
            // key is optional: without it the whole store is wiped (global sign-out).
            val key = (data as? Map<*, *>)?.get("key") as? String
            auth.storeClear(key) { result ->
                result.fold(
                    onSuccess = { reply.resolve(emptyMap<String, String>()) },
                    onFailure = { reply.reject(it.message ?: "error") },
                )
            }
        }
    }

    private fun requireString(data: Any?, name: String, call: String): String {
        val value = (data as? Map<*, *>)?.get(name) as? String
        check(!value.isNullOrEmpty()) { "$call requires {\"$name\": string}" }
        return value
    }

    private fun optionalString(data: Any?, name: String): String? =
        (data as? Map<*, *>)?.get(name) as? String

    private companion object {
        const val TAG = "host-android"
        // The grant is a ceiling: a call must be both declared by the bundle and
        // allowed here (nsh-core 0.4.0 access.rs), so name the mock hosts the
        // demo declares too; 10.0.2.2 is the emulator's alias for this Mac's loopback.
        const val HOST_GRANT =
            """{ "host": ["auth.authorize", "auth.pendingAuthorize", "auth.store.save", "auth.store.load", "auth.store.clear", "auth.config"], "network": { "hosts": ["127.0.0.1", "localhost", "10.0.2.2"] } }"""
    }
}
