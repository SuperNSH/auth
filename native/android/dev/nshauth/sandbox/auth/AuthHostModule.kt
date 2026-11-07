package dev.nshauth.sandbox.auth

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.util.Log
import androidx.browser.customtabs.CustomTabsIntent
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

class CancelledException(message: String) : RuntimeException(message)

/**
 * The nsh-auth host module: Custom Tabs authorize (browser selection, service
 * warm-up, URL prefetch, and a persisted record that survives process death),
 * Keystore-backed secure storage, and launch configuration. The host app wires
 * these onto the NshView channel as "auth.authorize", "auth.pendingAuthorize",
 * "auth.store.save|load|clear" and "auth.config".
 *
 * UI-thread state (config, pending, resumeArmed) is only touched from onCreate,
 * onNewIntent, onResume, onDestroy and the host handlers, which NshView runs on
 * the UI thread; the io executor serializes browser selection and store access.
 */
class AuthHostModule(private val activity: Activity) {

    /** What auth.config reports to the app; both fields may be absent. */
    data class Config(val mockBaseUrl: String? = null, val autoStart: String? = null)

    private class PendingAuth(val scheme: String, val onComplete: (Result<String>) -> Unit)

    /**
     * The sealed record that lets a redirect outlive this process. Persisted at
     * authorize time, resolved by a cold-start callback, reported through
     * auth.pendingAuthorize. It holds no token; the verifier is public in the
     * RFC 7636 sense: without its matching code it redeems nothing, and it only
     * ever travels to the token endpoint over TLS.
     */
    private data class PendingAuthorizeRecord(
        val scheme: String,
        val authorizeUrl: String,
        val state: String?,
        val provider: String?,
        val verifier: String?,
        val callbackUrl: String?,
    ) {
        fun toJson(): JSONObject =
            JSONObject()
                .put("scheme", scheme)
                .put("authorizeUrl", authorizeUrl)
                .putOpt("state", state)
                .putOpt("provider", provider)
                .putOpt("verifier", verifier)
                .putOpt("callbackUrl", callbackUrl)

        companion object {
            fun fromJson(raw: String): PendingAuthorizeRecord? {
                val obj = JSONObject(raw)
                fun opt(name: String): String? = obj.optString(name).takeIf { it.isNotEmpty() }
                val scheme = opt("scheme") ?: return null
                val url = opt("authorizeUrl") ?: return null
                return PendingAuthorizeRecord(scheme, url, opt("state"), opt("provider"), opt("verifier"), opt("callbackUrl"))
            }
        }
    }

    private var config = Config()
    private var pending: PendingAuth? = null
    private var resumeArmed = false

    // Storage touches files and the Keystore, browser selection queries the
    // package manager and binds a service: never run any of it on the UI thread.
    private val store = SecureStore(activity.applicationContext, File(activity.filesDir, STORE_FILE))
    private val io = Executors.newSingleThreadExecutor()
    private val tabManager = CustomTabManager(activity.applicationContext)

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
        val awaited = pending
        if (awaited != null) {
            // Only the exact registered scheme://callback (any query) completes a
            // pending authorize; the manifest filter still routes other URIs on this
            // scheme, and ignoring them keeps a forged intent from finishing the call.
            if (!matchesRedirect(data, awaited.scheme)) {
                // Never log the query: a non-matching redirect can still carry a live code/state.
                Log.w(TAG, "ignoring redirect that is not ${awaited.scheme}://$REGISTERED_REDIRECT_HOST: ${data.scheme}://${data.host}${data.path ?: ""}")
                return
            }
            pending = null
            resumeArmed = false
            clearPendingRecord()
            awaited.onComplete(Result.success(data.toString()))
            return
        }
        // No in-memory pending: this process was restarted since authorize and the
        // promise died with it. Resolve the persisted record instead, so the
        // relaunched app can still report (and consume) the interrupted flow.
        val scheme = data.scheme?.lowercase() ?: return
        io.execute {
            val record = readPendingRecord() ?: return@execute
            if (record.callbackUrl != null) return@execute
            if (!matchesRedirect(data, record.scheme)) return@execute
            try {
                store.save(PENDING_KEY, record.copy(callbackUrl = data.toString()).toJson().toString())
            } catch (e: Exception) {
                Log.w(TAG, "cannot persist the completed redirect", e)
            }
        }
    }

    /** The one redirect shape this module ever accepts: exact registered scheme, host and path. */
    private fun matchesRedirect(data: Uri, scheme: String): Boolean {
        val path = data.path
        return data.scheme?.lowercase() == scheme &&
            data.host?.lowercase() == REGISTERED_REDIRECT_HOST &&
            (path.isNullOrEmpty() || path == "/")
    }

    /**
     * Opens the authorize URL in a browser chosen by [BrowserSelector], and
     * completes with the callback URI. `verifier`, `state` and `provider` are
     * optional: whatever the caller supplies (state is also read from the URL's
     * query) is persisted with the pending record, so a cold-start redirect can
     * still be matched and reported after this process dies.
     */
    fun authorize(
        url: String,
        scheme: String,
        verifier: String?,
        state: String?,
        provider: String?,
        onComplete: (Result<String>) -> Unit,
    ) {
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
        val awaiting = PendingAuth(normalized, onComplete)
        pending = awaiting
        io.execute {
            // Up-front no-browser detection: reject instead of launching into nothing
            // (upstream throws ActivityNotFoundException from the same check).
            val descriptor = BrowserSelector.select(activity, AnyBrowserMatcher)
            if (descriptor == null) {
                activity.runOnUiThread {
                    if (pending !== awaiting) return@runOnUiThread
                    pending = null
                    onComplete(
                        Result.failure(
                            IllegalStateException(
                                "auth.authorize: no browser is installed on this device; the authorize URL cannot be opened",
                            ),
                        ),
                    )
                }
                return@execute
            }
            // On disk before the browser can leave the app: a process kill right
            // after launch still leaves a resumable record. A failed write only
            // degrades to the old memory-only behavior, it never fails the launch.
            persistPendingRecord(
                PendingAuthorizeRecord(
                    scheme = normalized,
                    authorizeUrl = url,
                    state = state ?: parsed.getQueryParameter("state"),
                    provider = provider,
                    verifier = verifier,
                    callbackUrl = null,
                ),
            )
            val tabsIntent =
                if (descriptor.useCustomTab) tabManager.createTabBuilder(parsed).setShowTitle(true).build() else null
            activity.runOnUiThread {
                if (pending !== awaiting) return@runOnUiThread
                if (tabsIntent != null) {
                    tabsIntent.intent.setPackage(descriptor.packageName)
                    tabsIntent.launchUrl(activity, parsed)
                } else {
                    // Upstream launches a plain ACTION_VIEW for browsers without custom tabs.
                    activity.startActivity(
                        Intent(Intent.ACTION_VIEW).setPackage(descriptor.packageName).setData(parsed),
                    )
                }
                // Backing out of the browser shows up only as a plain resume; decide there.
                resumeArmed = true
            }
        }
    }

    /**
     * The pending record as the app may consume it (`auth.pendingAuthorize`),
     * or an empty map when no flow is parked. With `clear`, the record is
     * dropped instead of reported (the app took over the flow).
     */
    fun pendingAuthorize(clear: Boolean, onReply: (Map<String, String>) -> Unit) {
        io.execute {
            if (clear) {
                runCatching { store.clear(PENDING_KEY) }
                    .onFailure { Log.w(TAG, "cannot clear the pending authorize record", it) }
                onReply(emptyMap())
                return@execute
            }
            val record = readPendingRecord() ?: run {
                onReply(emptyMap())
                return@execute
            }
            val out = LinkedHashMap<String, String>()
            out["scheme"] = record.scheme
            out["url"] = record.authorizeUrl
            record.state?.let { out["state"] = it }
            record.provider?.let { out["provider"] = it }
            record.verifier?.let { out["verifier"] = it }
            record.callbackUrl?.let { out["callbackUrl"] = it }
            onReply(out)
        }
    }

    private fun persistPendingRecord(record: PendingAuthorizeRecord) {
        try {
            store.save(PENDING_KEY, record.toJson().toString())
        } catch (e: Exception) {
            Log.w(TAG, "cannot persist the pending authorize record", e)
        }
    }

    private fun readPendingRecord(): PendingAuthorizeRecord? {
        val raw = try {
            store.load(PENDING_KEY)
        } catch (e: Exception) {
            Log.w(TAG, "cannot read the pending authorize record", e)
            null
        } ?: return null
        return runCatching { PendingAuthorizeRecord.fromJson(raw) }
            .onFailure { Log.w(TAG, "ignoring an unreadable pending authorize record") }
            .getOrNull()
    }

    private fun clearPendingRecord() {
        io.execute {
            runCatching { store.clear(PENDING_KEY) }
                .onFailure { Log.w(TAG, "cannot clear the pending authorize record", it) }
        }
    }

    fun onHostResumed() {
        if (!resumeArmed) return
        resumeArmed = false
        pending?.onComplete(Result.failure(CancelledException(CANCELLED)))
        pending = null
        // Cancel clears the record too: the browser backed out, nothing is in flight.
        clearPendingRecord()
    }

    /**
     * Destroy keeps the record on purpose: the browser may still be out there,
     * and its redirect (or the next authorize, which supersedes) resolves it.
     */
    fun onHostDestroyed() {
        pending?.onComplete(Result.failure(CancelledException("cancelled: host destroyed")))
        pending = null
        tabManager.dispose()
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
        // The non-session key holding the process-death record. Cleared by the
        // module on completion/cancel/supersede; auth.store.clear with no key
        // (global sign-out) wipes it too, which is the right scope for sign-out.
        const val PENDING_KEY = "nsh-auth.pending-authorize"
        // Must match the VIEW/BROWSABLE intent filter on MainActivity in the host manifest.
        const val REGISTERED_SCHEME = "nsh.auth.sandbox"
        const val REGISTERED_REDIRECT_HOST = "callback"
    }
}
