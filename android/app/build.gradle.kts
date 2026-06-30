import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
}

val zeroDpiRuntimeDir = providers.gradleProperty("zerodpiRuntimeDir")
    .map { file(it) }
fun stringPropertyOrEnv(name: String) =
    providers.gradleProperty(name).orElse(providers.environmentVariable(name))

val releaseStoreFile = stringPropertyOrEnv("ZERODPI_RELEASE_STORE_FILE")
val releaseStorePassword = stringPropertyOrEnv("ZERODPI_RELEASE_STORE_PASSWORD")
val releaseKeyAlias = stringPropertyOrEnv("ZERODPI_RELEASE_KEY_ALIAS")
val releaseKeyPassword = stringPropertyOrEnv("ZERODPI_RELEASE_KEY_PASSWORD")
val hasReleaseSigning = releaseStoreFile.isPresent &&
    releaseStorePassword.isPresent &&
    releaseKeyAlias.isPresent

android {
    namespace = "dev.zerodpi.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.zerodpi.android"
        minSdk = 23
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }

    signingConfigs {
        if (hasReleaseSigning) {
            create("zerodpiRelease") {
                storeFile = file(releaseStoreFile.get())
                storePassword = releaseStorePassword.get()
                keyAlias = releaseKeyAlias.get()
                keyPassword = releaseKeyPassword.orElse(releaseStorePassword).get()
            }
        }
    }

    buildTypes {
        debug {
            buildConfigField("boolean", "ZERODPI_ALLOW_FAKE_RUNNER", "true")
        }
        release {
            buildConfigField("boolean", "ZERODPI_ALLOW_FAKE_RUNNER", "false")
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("zerodpiRelease")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    sourceSets {
        getByName("main") {
            zeroDpiRuntimeDir.orNull?.let { runtimeDir ->
                assets.setSrcDirs(listOf(runtimeDir.resolve("assets")))
                jniLibs.srcDir(runtimeDir.resolve("jniLibs"))
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(platform("androidx.compose:compose-bom:2026.05.01"))
    implementation("androidx.activity:activity-compose:1.12.4")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.10.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    testImplementation("junit:junit:4.13.2")

    androidTestImplementation(platform("androidx.compose:compose-bom:2026.05.01"))
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:rules:1.7.0")
    androidTestImplementation("androidx.test:runner:1.7.0")

    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
