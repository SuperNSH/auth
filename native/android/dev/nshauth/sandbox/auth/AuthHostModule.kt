package dev.nshauth.sandbox.auth

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.browser.customtabs.CustomTabsIntent
import java.io.File
import java.util.concurrent.Executors

class CancelledException(message: String) : RuntimeException(message)

/**
 * The nsh-auth host module: Custom Tabs authorize, Keystore-backed secure
 * storage, and launch configuration. The host app wires these onto the NshView
 * channel as "auth.authorize", "auth.store.save|load|clear" and "auth.config".
 *
 * UI-thread state (config, pending) is only touched from onCreate, onNewIntent,
 * onResume, onDestroy and the host handlers, which NshView runs on the UI thread.
 */
class AuthHostModule(private val activity: Activity) {

    /** What auth.config reports to the app; both fields may be absent. */
    data class Config(val mockBaseUrl: String? = null, val autoStart: String? = null)

    private class PendingAuth(val scheme: String, val onComplete: (Result<String>) -> Unit)

    private var config = Config()
    private var pending: PendingAuth? = null
    private var resumeArmed = false

    // Storage touches files and the Keystore: never run it on the UI thread.
    private val store = SecureStore(File(activity.filesDir, STORE_FILE))
    private val io = Executors.newSingleThreadExecutor()

    fun configReply(): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        config.mockBaseUrl?.let { out["mockBaseUrl"] = it }
        config.autoStart?.let { out["autoStart"] = it }
        return out
    }

    /** host.params, read once when the app loads; the host owns the redirect URI. */
    fun paramsReply(): Map<String, Any> {
        val auth = LinkedHashMap<String, Any>()
        auth["redirectUri"] = registeredRedirectUri()
        config.mockBaseUrl?.let { auth["mockBaseUrl"] = it }
        config.autoStart?.let { auth["autoStart"] = it }
        return mapOf("auth" to auth)
    }

    /** The redirect URI the host manifest actually routes (the VIEW/BROWSABLE intent filter). */
    fun registeredRedirectUri(): String = "$REGISTERED_SCHEME://$REGISTERED_REDIRECT_HOST"

    /**
     * onCreate only: reads the cold-launch intent's config extras (a warm
     * instance's onNewIntent never reconfigures sign-in) and completes a
     * pending authorize on a cold-start redirect. No action gate: `am start -n`
     * sends no action, and the extras are launch arguments, not a redirect.
     */
    fun handleLaunchIntent(intent: Intent?) {
        if (intent == null) return
        intent.getStringExtra(EXTRA_PROVIDER)?.let { config = config.copy(autoStart = it) }
        intent.getStringExtra(EXTRA_MOCK_BASE_URL)?.let { config = config.copy(mockBaseUrl = normalizeMockUrl(it)) }
        completeRedirect(intent)
    }

    /** onNewIntent only: completes a pending authorize; never reads launch extras. */
    fun handleRedirectIntent(intent: Intent?) {
        completeRedirect(intent)
    }

    private fun completeRedirect(intent: Intent?) {
        if (intent == null) return
        val data = intent.data ?: return
        val awaited = pending ?: return
        // Only the exact registered scheme://callback (any query) completes a
        // pending authorize; the manifest filter still routes other URIs on this
        // scheme, and ignoring them keeps a forged intent from finishing the call.
        val path = data.path
        val matches = data.scheme?.lowercase() == awaited.scheme &&
            data.host?.lowercase() == REGISTERED_REDIRECT_HOST &&
            (path.isNullOrEmpty() || path == "/")
        if (!matches) {
            // Never log the query: a non-matching redirect can still carry a live code/state.
            Log.w(TAG, "ignoring redirect that is not ${awaited.scheme}://$REGISTERED_REDIRECT_HOST: ${data.scheme}://${data.host}${data.path ?: ""}")
            return
        }
        pending = null
        resumeArmed = false
        awaited.onComplete(Result.success(data.toString()))
    }

    fun authorize(url: String, scheme: String, onComplete: (Result<String>) -> Unit) {
        val parsed = Uri.parse(url)
        if (parsed.scheme != "https" && parsed.scheme != "http") {
            onComplete(Result.failure(IllegalArgumentException("auth.authorize: url must be http(s), got \"$url\"")))
            return
        }
        // A scheme the host manifest does not route can never legitimately
        // return, so refuse it instead of leaving an authorize that only a
        // forged intent could complete.
        val normalized = scheme.lowercase()
        if (normalized != REGISTERED_SCHEME) {
            onComplete(
                Result.failure(
                    IllegalArgumentException(
                        "auth.authorize: scheme \"$scheme\" is not registered in the host manifest (registered: $REGISTERED_SCHEME)",
                    ),
                ),
            )
            return
        }
        pending?.onComplete(Result.failure(CancelledException("cancelled: superseded by a new authorize call")))
        pending = PendingAuth(normalized, onComplete)
        CustomTabsIntent.Builder().setShowTitle(true).build().launchUrl(activity, parsed)
        // Backing out of Custom Tabs shows up only as a plain resume; decide there.
        resumeArmed = true
    }

    fun onHostResumed() {
        if (!resumeArmed) return
        resumeArmed = false
        pending?.onComplete(Result.failure(CancelledException(CANCELLED)))
        pending = null
    }

    fun onHostDestroyed() {
        pending?.onComplete(Result.failure(CancelledException("cancelled: host destroyed")))
        pending = null
        io.shutdown()
    }

    fun storeSave(key: String, value: String, onComplete: (Result<Unit>) -> Unit) {
        io.execute { onComplete(runCatching { store.save(key, value) }) }
    }

    fun storeLoad(key: String, onComplete: (Result<String?>) -> Unit) {
        io.execute { onComplete(runCatching { store.load(key) }) }
    }

    fun storeClear(key: String?, onComplete: (Result<Unit>) -> Unit) {
        io.execute { onComplete(runCatching { store.clear(key) }) }
    }

    // The emulator cannot reach the host machine's loopback; its alias for it is 10.0.2.2.
    private fun normalizeMockUrl(raw: String): String {
        if (!isEmulator) return raw
        val uri = Uri.parse(raw)
        val authority = uri.encodedAuthority ?: return raw
        if (!authority.startsWith("localhost") && !authority.startsWith("127.0.0.1")) return raw
        val rewritten = authority.replaceFirst("localhost", "10.0.2.2").replaceFirst("127.0.0.1", "10.0.2.2")
        return uri.buildUpon().encodedAuthority(rewritten).build().toString()
    }

    private val isEmulator: Boolean =
        Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.startsWith("unknown") ||
            Build.MODEL.contains("google_sdk") || Build.MODEL.contains("Emulator") ||
            Build.MODEL.contains("Android SDK built for") || Build.MANUFACTURER.contains("Genymotion") ||
            (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) ||
            Build.PRODUCT == "google_sdk" || Build.PRODUCT.startsWith("sdk_gphone")

    private companion object {
        const val TAG = "AuthHostModule"
        const val EXTRA_PROVIDER = "provider"
        const val EXTRA_MOCK_BASE_URL = "mockBaseUrl"
        const val CANCELLED = "cancelled"
        const val STORE_FILE = "nsh-auth-store.json"
        // Must match the VIEW/BROWSABLE intent filter on MainActivity in the host manifest.
        const val REGISTERED_SCHEME = "nsh.auth.sandbox"
        const val REGISTERED_REDIRECT_HOST = "callback"
    }
}
