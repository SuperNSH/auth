/*
 * Copyright 2016 The AppAuth for Android Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modified by nsh-auth (2026-11-07) vs upstream openid/AppAuth-Android e5f5184
 * (library/java/net/openid/appauth/browser/BrowserDescriptor.java): translated to
 * Kotlin, repackaged to dev.nshauth.sandbox.auth, `version` is nullable
 * (PackageInfo.versionName can be null), equals/hashCode use Kotlin's data-class
 * semantics (upstream's prime-mixed hash is not persisted anywhere),
 * changeUseCustomTab dropped as dead code (no matcher here mutates descriptors).
 */
package dev.nshauth.sandbox.auth

import android.content.pm.PackageInfo
import android.content.pm.Signature
import android.util.Base64
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

/**
 * Represents a browser that may be used for an authorization flow.
 */
data class BrowserDescriptor(
    /** The package name of the browser app. */
    val packageName: String,
    /**
     * The set of [Signature signatures] of the browser app, hashed with SHA-512
     * and Base64 URL-safe encoded. Unused by the matcher below (we adopt
     * upstream's allow-all matcher, not the version catalogue), kept because the
     * descriptor's equality and its consumers' contract include it.
     */
    val signatureHashes: Set<String>,
    /** The version string of the browser app. */
    val version: String?,
    /** Whether it is intended that the browser will be used via a custom tab. */
    val useCustomTab: Boolean,
) {
    /**
     * Creates a description of a browser from a [PackageInfo] object returned from the
     * [android.content.pm.PackageManager]. The object is expected to include the
     * signatures of the app, which can be retrieved with the
     * [android.content.pm.PackageManager#GET_SIGNATURES GET_SIGNATURES] flag when
     * calling [android.content.pm.PackageManager#getPackageInfo(String, int)].
     */
    @Suppress("DEPRECATION") // GET_SIGNATURES, as upstream
    constructor(packageInfo: PackageInfo, useCustomTab: Boolean) : this(
        packageInfo.packageName,
        generateSignatureHashes(packageInfo.signatures ?: emptyArray()),
        packageInfo.versionName,
        useCustomTab,
    )

    companion object {
        /**
         * Generates a SHA-512 hash, Base64 url-safe encoded, from a [Signature].
         */
        fun generateSignatureHash(signature: Signature): String = try {
            val digest = MessageDigest.getInstance(DIGEST_SHA_512)
            val hashBytes = digest.digest(signature.toByteArray())
            Base64.encodeToString(hashBytes, Base64.URL_SAFE or Base64.NO_WRAP)
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException("Platform does not support$DIGEST_SHA_512 hashing")
        }

        /**
         * Generates a set of SHA-512, Base64 url-safe encoded signature hashes from the provided
         * array of signatures.
         */
        fun generateSignatureHashes(signatures: Array<Signature>): Set<String> =
            signatures.mapTo(HashSet()) { generateSignatureHash(it) }

        private const val DIGEST_SHA_512 = "SHA-512"
    }
}
