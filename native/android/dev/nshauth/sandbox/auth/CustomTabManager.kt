/*
 * Copyright 2015 The AppAuth for Android Authors. All Rights Reserved.
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
 * (library/java/net/openid/appauth/browser/CustomTabManager.java): translated to
 * Kotlin, repackaged to dev.nshauth.sandbox.auth; upstream's internal Logger
 * became android.util.Log; createSession takes the one authorize URI (upstream's
 * varargs + UriUtil.toCustomTabUriBundle built a bundle of alternates we do not
 * have) and the surface is narrowed to bind/createTabBuilder/dispose. As
 * upstream, dispose() is terminal: the latch is single-shot.
 */
package dev.nshauth.sandbox.auth

import android.content.ComponentName
import android.content.Context
import android.net.Uri
import android.util.Log
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import androidx.browser.customtabs.CustomTabsServiceConnection
import androidx.browser.customtabs.CustomTabsSession
import java.lang.ref.WeakReference
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Hides the details of establishing connections and sessions with custom tabs, to make testing
 * easier.
 */
internal class CustomTabManager(context: Context) {

    /**
     * Wait for at most this amount of time for the browser connection to be established.
     */
    private val clientWaitTimeMs = 1_000L

    private val contextRef = WeakReference(context)

    private val client = AtomicReference<CustomTabsClient?>(null)

    private val clientLatch = CountDownLatch(1)

    private var connection: CustomTabsServiceConnection? = null

    @Synchronized
    fun bind(browserPackage: String) {
        if (connection != null) {
            return
        }

        val newConnection = object : CustomTabsServiceConnection() {
            override fun onCustomTabsServiceConnected(
                componentName: ComponentName,
                customTabsClient: CustomTabsClient,
            ) {
                Log.d(TAG, "CustomTabsService is connected")
                customTabsClient.warmup(0)
                setClient(customTabsClient)
            }

            override fun onServiceDisconnected(componentName: ComponentName) {
                Log.d(TAG, "CustomTabsService is disconnected")
                setClient(null)
            }

            private fun setClient(value: CustomTabsClient?) {
                client.set(value)
                clientLatch.countDown()
            }
        }
        connection = newConnection

        val context = contextRef.get()
        if (context == null ||
            !CustomTabsClient.bindCustomTabsService(context, browserPackage, newConnection)
        ) {
            // this is expected if the browser does not support custom tabs
            Log.i(TAG, "Unable to bind custom tabs service")
            clientLatch.countDown()
        }
    }

    /**
     * Creates a [CustomTabsIntent.Builder custom tab builder], warming up the bound browser
     * and asking it to prefetch `possibleUri` (the authorize URL) while the tab opens.
     * If the selected browser does not support custom tabs, the prefetch has no effect and
     * the builder falls back to a plain session-less tab. Must not run on the UI thread.
     */
    fun createTabBuilder(possibleUri: Uri?): CustomTabsIntent.Builder =
        CustomTabsIntent.Builder(createSession(possibleUri))

    @Synchronized
    fun dispose() {
        val bound = connection ?: return
        contextRef.get()?.unbindService(bound)
        connection = null
        client.set(null)
        Log.d(TAG, "CustomTabsService is disconnected")
    }

    /**
     * Creates a [CustomTabsSession custom tab session] for use with a custom tab intent,
     * calling [CustomTabsSession.mayLaunchUrl] for `possibleUri` so the browser prefetches
     * it. Returns null when no custom-tab-capable browser connected within the wait time.
     */
    private fun createSession(possibleUri: Uri?): CustomTabsSession? {
        val connectedClient = getClient() ?: return null

        val session = connectedClient.newSession(null)
        if (session == null) {
            Log.w(TAG, "Failed to create custom tabs session through custom tabs client")
            return null
        }

        possibleUri?.let { session.mayLaunchUrl(it, null, null) }

        return session
    }

    /**
     * Retrieve the custom tab client used to communicate with the custom tab supporting browser,
     * if available.
     */
    private fun getClient(): CustomTabsClient? {
        try {
            clientLatch.await(clientWaitTimeMs, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Log.i(TAG, "Interrupted while waiting for browser connection")
            clientLatch.countDown()
        }

        return client.get()
    }

    private companion object {
        const val TAG = "AuthCustomTabManager"
    }
}
