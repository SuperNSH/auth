package dev.nshauth.sandbox.auth

import android.app.Activity
import android.content.Intent
import android.util.Log
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import com.facebook.AccessToken
import com.facebook.CallbackManager
import com.facebook.FacebookCallback
import com.facebook.FacebookException
import com.facebook.login.LoginManager
import com.facebook.login.LoginResult
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential

/**
 * Native SDK sign-in behind `auth.nativeSignIn`: Google through Credential
 * Manager (androidx.credentials 1.6.0 + googleid 1.2.1), Facebook through
 * facebook-login 19.0.1. Unlike auth.authorize there is no persisted record:
 * both SDKs own their state, so a flow killed mid-dialog leaves nothing
 * pending on our side - the app just calls nativeSignIn again.
 *
 * The Google server client id is injected by the host (constructor param),
 * read from SERVER_CLIENT_ID_METADATA in the app's manifest: the returned
 * id_token's aud carries it, so a hard-coded sandbox id would make the core's
 * aud check unreachable for a real Google config. Neither credentials 1.6.0
 * nor googleid 1.2.1 defines a manifest key for it (verified in the resolved
 * AARs), so this host-owned key is the contract, and absence rejects google
 * sign-in loudly - never a silent fallback to the sandbox value.
 *
 * The plain Activity this host runs NshView in works for both SDKs: the
 * Credential Manager play-services bridge launches its own HiddenActivity from
 * an activity context (CredentialProviderController's stated requirement is
 * only "Activity-based context", no ComponentActivity/FragmentActivity), and
 * facebook-login's logIn(Activity, ...) overload exists exactly for activities
 * that are not an ActivityResultRegistryOwner.
 */
class NativeSignInModule(
    private val activity: Activity,
    private val serverClientId: String?,
) {

    private val callbackManager = CallbackManager.Factory.create()
    private var pending: ((Result<Map<String, Any>>) -> Unit)? = null

    /**
     * Starts a provider sign-in. `nonce` (the RAW nonce from the core) is
     * bound by Google's Credential Manager verbatim into the returned
     * id_token; Facebook's SDK login carries no nonce through this path.
     * Resolves {provider:"google", idToken, nonce?} or
     * {provider:"facebook", accessToken, expiresAt}; rejects "cancelled" on
     * user cancel, otherwise with the SDK's own error message - or, for
     * google without a server client id from the host manifest, the
     * configuration error (no sandbox fallback).
     */
    fun nativeSignIn(provider: String, nonce: String?, onComplete: (Result<Map<String, Any>>) -> Unit) {
        pending?.invoke(Result.failure(CancelledException(CANCELLED_SUPERSEDED)))
        pending = onComplete
        when (provider) {
            GOOGLE -> googleSignIn(nonce)
            FACEBOOK -> facebookSignIn()
            else -> {
                pending = null
                onComplete(
                    Result.failure(
                        IllegalArgumentException("auth.nativeSignIn: unknown provider \"$provider\" (known: $GOOGLE, $FACEBOOK)"),
                    ),
                )
            }
        }
    }

    private fun googleSignIn(nonce: String?) {
        if (serverClientId.isNullOrBlank()) {
            finish(
                Result.failure(
                    IllegalStateException(
                        "auth.nativeSignIn google: host manifest meta-data \"$SERVER_CLIENT_ID_METADATA\" is missing; " +
                            "set it to the app's Google web client id (the id_token aud the core must verify)",
                    ),
                ),
            )
            return
        }
        // googleid 1.2.1's Builder has setNonce (verified in the resolved AAR):
        // Android-Google does bind the nonce, unlike iOS-Apple's sha256 rule.
        val option =
            GetGoogleIdOption.Builder()
                .setServerClientId(serverClientId)
                .setFilterByAuthorizedAccounts(false)
                .apply { nonce?.let(::setNonce) }
                .build()
        val request = GetCredentialRequest.Builder().addCredentialOption(option).build()
        CredentialManager.create(activity)
            .getCredentialAsync(
                activity,
                request,
                null,
                Runnable::run,
                object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                    override fun onResult(result: GetCredentialResponse) {
                        val credential = result.credential
                        if (credential.type != GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL) {
                            Log.w(TAG, "unexpected credential type ${credential.type}")
                            finish(
                                Result.failure(
                                    IllegalStateException(
                                        "auth.nativeSignIn: google returned credential type \"${credential.type}\" instead of an id token",
                                    ),
                                ),
                            )
                            return
                        }
                        val out = LinkedHashMap<String, Any>()
                        out["provider"] = GOOGLE
                        out["idToken"] = GoogleIdTokenCredential.createFrom(credential.data).idToken
                        nonce?.let { out["nonce"] = it }
                        finish(Result.success(out))
                    }

                    override fun onError(e: GetCredentialException) {
                        // With our unregistered sandbox client id this is
                        // Google's own error surfaced by Credential Manager -
                        // the expected on-device outcome per docs/PROMPT.md.
                        if (e is GetCredentialCancellationException) {
                            finish(Result.failure(CancelledException(CANCELLED)))
                        } else {
                            Log.w(TAG, "google sign-in failed: ${e.type}")
                            finish(Result.failure(e))
                        }
                    }
                },
            )
    }

    private fun facebookSignIn() {
        // Init without manifest meta-data does not crash in 19.0.1 (the
        // FacebookInitProvider catch-and-logs at INFO): the host manifest
        // carries both entries so the failure stays at Facebook's surface.
        val manager = LoginManager.getInstance()
        manager.registerCallback(
            callbackManager,
            object : FacebookCallback<LoginResult> {
                override fun onSuccess(result: LoginResult) {
                    val token = AccessToken.getCurrentAccessToken() ?: result.accessToken
                    finish(
                        Result.success(
                            mapOf(
                                "provider" to FACEBOOK,
                                "accessToken" to token.token,
                                "expiresAt" to token.expires.time,
                            ),
                        ),
                    )
                }

                override fun onCancel() {
                    finish(Result.failure(CancelledException(CANCELLED)))
                }

                override fun onError(error: FacebookException) {
                    finish(Result.failure(error))
                }
            },
        )
        // The registry-based logIn overload needs a ComponentActivity; this
        // host's plain Activity takes the Activity overload, whose result
        // arrives through onActivityResult below.
        manager.logIn(activity, listOf(PUBLIC_PROFILE, EMAIL))
    }

    /** MainActivity.onActivityResult forwards here; false means not a Facebook result. */
    fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?): Boolean =
        callbackManager.onActivityResult(requestCode, resultCode, data)

    private fun finish(result: Result<Map<String, Any>>) {
        activity.runOnUiThread {
            val awaiting = pending ?: return@runOnUiThread
            pending = null
            awaiting(result)
        }
    }

    fun onHostDestroyed() {
        pending?.invoke(Result.failure(CancelledException("cancelled: host destroyed")))
        pending = null
    }

    companion object {
        // Host-owned key (no credentials/googleid manifest key exists): the
        // app's Google web client id; the sandbox host manifest carries the
        // obviously-fake sandbox value (docs/PROMPT.md: never a real one).
        const val SERVER_CLIENT_ID_METADATA = "nsh.auth.server-client-id"

        private const val TAG = "NativeSignInModule"
        private const val CANCELLED = "cancelled"
        private const val CANCELLED_SUPERSEDED = "cancelled: superseded by a new nativeSignIn call"
        private const val GOOGLE = "google"
        private const val FACEBOOK = "facebook"
        private const val PUBLIC_PROFILE = "public_profile"
        private const val EMAIL = "email"
    }
}
