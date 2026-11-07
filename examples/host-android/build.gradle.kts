buildscript {
    repositories {
        google()
        mavenCentral()
    }
    dependencies {
        // AGP 9's built-in Kotlin is this artifact (AGP POM pins 2.2.10, whose
        // compiler reads metadata only up to 2.3.0); googleid 1.2.1 ships
        // 2.4.0 metadata, so the engine is forced to a version that reads it.
        // Every AGP stable line up to 9.5.1 pins 2.2.10 - no AGP bump fixes it.
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:2.4.10")
    }
}

plugins {
    id("com.android.application") version "9.1.0" apply false
}
