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
 * (library/java/net/openid/appauth/browser/BrowserSelector.java): translated to
 * Kotlin, repackaged to dev.nshauth.sandbox.auth; the MATCH_ALL version gate was
 * dropped (our minSdk 28 is above API 23); BrowserMatcher became a fun interface
 * and AnyBrowserMatcher was adopted here from upstream Browsers.java instead of
 * vendoring the whole versioned catalogue (we do not pin browser versions).
 */
package dev.nshauth.sandbox.auth

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ResolveInfo
import android.net.Uri
import androidx.browser.customtabs.CustomTabsService

/**
 * Matches a [BrowserDescriptor]; upstream's matcher interface (a single method,
 * so a `fun interface` here).
 */
fun interface BrowserMatcher {
    fun matches(descriptor: BrowserDescriptor): Boolean
}

/**
 * Matches every full browser. The upstream default when no allow-list is
 * configured, and what this host uses: it deliberately does not pin browser
 * versions or signatures.
 */
object AnyBrowserMatcher : BrowserMatcher {
    override fun matches(descriptor: BrowserDescriptor): Boolean = true
}

/**
 * Utility class to obtain the browser package name to be used for launching an
 * authorization flow in a browser. It prioritizes browsers which support
 * [custom tabs](https://developer.chrome.com/multidevice/android/customtabs). To mitigate
 * man-in-the-middle attacks by malicious apps pretending to be browsers for the specific URI we
 * query, only those which are registered as a handler for _all_ HTTP and HTTPS URIs will be
 * used.
 */
internal object BrowserSelector {

    private const val SCHEME_HTTP = "http"
    private const val SCHEME_HTTPS = "https"

    /**
     * The service we expect to find on a web browser that indicates it supports custom tabs.
     */
    private val ACTION_CUSTOM_TABS_CONNECTION = CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION

    /**
     * Intent for querying installed web browsers as seen at
     * https://cs.android.com/android/platform/superproject/+/master:packages/modules/Permission/PermissionController/src/com/android/permissioncontroller/role/model/BrowserRoleBehavior.java
     */
    private val BROWSER_INTENT: Intent = Intent()
        .setAction(Intent.ACTION_VIEW)
        .addCategory(Intent.CATEGORY_BROWSABLE)
        .setData(Uri.fromParts("http", "", null))

    /**
     * Retrieves the full list of browsers installed on the device. Two entries will exist
     * for each browser that supports custom tabs, with the [BrowserDescriptor.useCustomTab]
     * flag set to `true` in one and `false` in the other. The list is in the
     * order returned by the package manager, so indirectly reflects the user's preferences
     * (i.e. their default browser, if set, should be the first entry in the list).
     */
    @Suppress("DEPRECATION") // GET_SIGNATURES, as upstream
    fun getAllBrowsers(context: Context): List<BrowserDescriptor> {
        val pm = context.packageManager
        val browsers = ArrayList<BrowserDescriptor>()
        var defaultBrowserPackage: String? = null

        // When requesting all matching activities for an intent from the package manager,
        // the user's preferred browser is not guaranteed to be at the head of this list.
        // Therefore, the preferred browser must be separately determined and the resultant
        // list of browsers reordered to restored this desired property.
        pm.resolveActivity(BROWSER_INTENT, 0)?.let {
            defaultBrowserPackage = it.activityInfo.packageName
        }
        // GET_RESOLVED_FILTER or MATCH_ALL: the filters are read below, and the SDK
        // floor (28) is above the MATCH_ALL introduction (23), so no version gate.
        val queryFlag = PackageManager.GET_RESOLVED_FILTER or PackageManager.MATCH_ALL
        val resolvedActivityList = pm.queryIntentActivities(BROWSER_INTENT, queryFlag)

        for (info in resolvedActivityList) {
            // ignore handlers which are not browsers
            if (!isFullBrowser(info)) {
                continue
            }

            try {
                val isDefaultBrowser = info.activityInfo.packageName == defaultBrowserPackage
                var defaultBrowserIndex = 0
                val packageInfo = pm.getPackageInfo(
                    info.activityInfo.packageName,
                    PackageManager.GET_SIGNATURES,
                )

                if (hasWarmupService(pm, info.activityInfo.packageName)) {
                    val customTabBrowserDescriptor = BrowserDescriptor(packageInfo, true)
                    if (isDefaultBrowser) {
                        // If the default browser is having a WarmupService,
                        // will it be added to the beginning of the list.
                        browsers.add(defaultBrowserIndex, customTabBrowserDescriptor)
                        defaultBrowserIndex++
                    } else {
                        browsers.add(customTabBrowserDescriptor)
                    }
                }

                val fullBrowserDescriptor = BrowserDescriptor(packageInfo, false)
                if (isDefaultBrowser) {
                    // The default browser is added to the beginning of the list.
                    // If there is support for Custom Tabs, will the one disabling Custom Tabs
                    // be added as the second entry.
                    browsers.add(defaultBrowserIndex, fullBrowserDescriptor)
                } else {
                    browsers.add(fullBrowserDescriptor)
                }
            } catch (_: PackageManager.NameNotFoundException) {
                // a descriptor cannot be generated without the package info
            }
        }

        return browsers
    }

    /**
     * Searches through all browsers for the best match based on the supplied browser matcher.
     * Custom tab supporting browsers are preferred, if the matcher permits them, and browsers
     * are evaluated in the order returned by the package manager, which should indirectly match
     * the user's preferences.
     *
     * @return The descriptor recommended to use for the authorization flow, or null when
     * no full browser matches (the caller must not launch into nothing).
     */
    fun select(context: Context, browserMatcher: BrowserMatcher): BrowserDescriptor? {
        val allBrowsers = getAllBrowsers(context)
        var bestMatch: BrowserDescriptor? = null
        for (browser in allBrowsers) {
            if (!browserMatcher.matches(browser)) {
                continue
            }

            if (browser.useCustomTab) {
                // directly return the first custom tab supporting browser that is matched
                return browser
            }

            if (bestMatch == null) {
                // store this as the best match for use if we don't find any matching
                // custom tab supporting browsers
                bestMatch = browser
            }
        }

        return bestMatch
    }

    private fun hasWarmupService(pm: PackageManager, packageName: String): Boolean {
        val serviceIntent = Intent()
        serviceIntent.setAction(ACTION_CUSTOM_TABS_CONNECTION)
        serviceIntent.setPackage(packageName)
        return pm.resolveService(serviceIntent, 0) != null
    }

    private fun isFullBrowser(resolveInfo: ResolveInfo): Boolean {
        // The filter must match ACTION_VIEW, CATEGORY_BROWSEABLE, and at least one scheme,
        val filter = resolveInfo.filter
        if (filter == null ||
            !filter.hasAction(Intent.ACTION_VIEW) ||
            !filter.hasCategory(Intent.CATEGORY_BROWSABLE) ||
            filter.schemesIterator() == null
        ) {
            return false
        }

        // The filter must not be restricted to any particular set of authorities
        if (filter.authoritiesIterator() != null) {
            return false
        }

        // The filter must support both HTTP and HTTPS.
        var supportsHttp = false
        var supportsHttps = false
        val schemeIter = filter.schemesIterator()
        while (schemeIter.hasNext()) {
            val scheme = schemeIter.next()
            supportsHttp = supportsHttp or (SCHEME_HTTP == scheme)
            supportsHttps = supportsHttps or (SCHEME_HTTPS == scheme)

            if (supportsHttp && supportsHttps) {
                return true
            }
        }

        // at least one of HTTP or HTTPS is not supported
        return false
    }
}
