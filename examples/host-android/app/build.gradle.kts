plugins {
    id("com.android.application")
}

android {
    namespace = "dev.nshauth.sandbox"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.nshauth.sandbox"
        // The floor the nsh AAR declares in its own manifest.
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            // AuthHostModule, SecureStore and NativeSignInModule live under
            // native/android; one source of truth, no copied file.
            kotlin.srcDir("../../../native/android")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
}

dependencies {
    // The nsh AARs are not vendored: build-gate.sh copies them from
    // $(brew --prefix nsh)/libexec/embed/android into app/libs. The dev variant
    // talks to `nsh dev` and is linked in Debug builds only.
    debugImplementation(files("libs/nsh-dev.aar"))
    releaseImplementation(files("libs/nsh.aar"))
    implementation("androidx.browser:browser:1.8.0")
    // auth.nativeSignIn adapters. Exact versions pinned (no ranges, no `+`):
    // resolution hits dl.google.com (androidx.credentials) and repo1.maven.org
    // (facebook-login); see build-gate.sh / README for the network step.
    // credentials-play-services-auth is the GMS bridge that makes
    // GetGoogleIdOption work outside bare-metal devices.
    implementation("androidx.credentials:credentials:1.6.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.6.0")
    implementation("com.google.android.libraries.identity.googleid:googleid:1.2.1")
    implementation("com.facebook.android:facebook-login:19.0.1")
}

// Aligned with compileOptions above; a mismatch fails the Kotlin compile.
kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

val demoDir = rootDir.parentFile.resolve("demo")

// The demo's documented embed command: in a fenced block of examples/demo/README.md,
// the line naming host-android (the demo documents iOS and Android embeds side by
// side and lists an unrelated debug `nsh build` earlier), else the first
// `nsh build` line, else the standard release build. Keep in sync with the same
// logic in ../build-gate.sh.
val demoBuildCommand: String = run {
    val readme = demoDir.resolve("README.md")
    if (!readme.isFile) return@run "nsh build --release"
    var inBlock = false
    var first: String? = null
    for (line in readme.readLines()) {
        if (line.trimStart().startsWith("```")) {
            inBlock = !inBlock
            continue
        }
        if (!inBlock || !line.contains("nsh build")) continue
        if (line.contains("host-android")) return@run line.trim()
        if (first == null) first = line.trim()
    }
    first ?: "nsh build --release"
}

val assetsNsh = File(projectDir, "src/main/assets/nsh")

val verifyHostLibs by tasks.registering {
    doLast {
        check(file("libs/nsh-dev.aar").isFile && file("libs/nsh.aar").isFile) {
            "nsh AARs are missing from app/libs - run examples/host-android/build-gate.sh first"
        }
    }
}

val buildDemoBundle by tasks.registering {
    inputs.property("command", demoBuildCommand)
    inputs.files(fileTree(demoDir) { exclude("node_modules", ".git", ".gradle") })
    outputs.dir(assetsNsh)
    doLast {
        val startedAt = System.currentTimeMillis()
        logger.lifecycle("demo bundle: $demoBuildCommand (cwd ${demoDir.path})")
        val proc = ProcessBuilder("bash", "-c", demoBuildCommand)
            .directory(demoDir)
            .inheritIO()
            .start()
        val code = proc.waitFor()
        check(code == 0) { "the demo bundle build failed with exit code $code" }

        // nsh build writes wherever the demo documents (default .nsh/out), so the
        // fresh output is found by mtime, not by a fixed path.
        val fresh = demoDir.walkTopDown()
            .onEnter { dir -> dir.name != "node_modules" && dir.name != ".git" && dir.name != ".gradle" }
            .filter { it.isFile && it.name == "bundle.nshc" && it.lastModified() >= startedAt }
            .maxByOrNull { it.lastModified() }
        if (fresh == null) {
            // The demo command may target the assets directory directly.
            val direct = assetsNsh.resolve("bundle.nshc")
            check(direct.isFile && direct.lastModified() >= startedAt) {
                "the demo build produced no bundle.nshc under ${demoDir.path}"
            }
        } else {
            val bundleDir = fresh.parentFile
            if (bundleDir.canonicalPath != assetsNsh.canonicalPath) {
                assetsNsh.deleteRecursively()
                check(assetsNsh.mkdirs() || assetsNsh.isDirectory) { "cannot create ${assetsNsh.path}" }
                val entries = bundleDir.listFiles() ?: error("cannot list ${bundleDir.path}")
                for (entry in entries) {
                    if (entry.isDirectory) {
                        entry.copyRecursively(assetsNsh.resolve(entry.name))
                    } else {
                        entry.copyTo(assetsNsh.resolve(entry.name), overwrite = true)
                    }
                }
            }
            logger.lifecycle("demo bundle embedded at ${assetsNsh.path}")
        }
    }
}

tasks.named("preBuild") {
    dependsOn(verifyHostLibs, buildDemoBundle)
}
