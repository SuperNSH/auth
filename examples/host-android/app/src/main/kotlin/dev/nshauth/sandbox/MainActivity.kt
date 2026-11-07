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
            auth.authorize(url, scheme) { result ->
                result.fold(
                    onSuccess = { reply.resolve(mapOf("callbackUrl" to it)) },
                    onFailure = { reply.reject(it.message ?: "error") },
                )
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

    private companion object {
        const val TAG = "host-android"
        // Must stay in sync with the demo's nsh.json "capabilities.host".
        const val HOST_GRANT =
            """{ "host": ["auth.authorize", "auth.store.save", "auth.store.load", "auth.store.clear", "auth.config"] }"""
    }
}
