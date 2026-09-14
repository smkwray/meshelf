plugins {
    id("com.android.application")
}

android {
    namespace = "com.meshelf.android"
    compileSdk = 37
    buildToolsVersion = "37.0.0"
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.meshelf.android"
        minSdk = 26
        targetSdk = 37
        versionCode = 36
        versionName = "0.3.24-zip-folders"
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets.getByName("main").jniLibs.srcDir("src/main/jniLibs")

    testOptions {
        unitTests.isIncludeAndroidResources = false
    }
}

dependencies {
    implementation("androidx.activity:activity-ktx:1.13.0")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.camera:camera-core:1.6.2")
    implementation("androidx.camera:camera-camera2:1.6.2")
    implementation("androidx.camera:camera-lifecycle:1.6.2")
    implementation("androidx.camera:camera-view:1.6.2")

    testImplementation("junit:junit:4.13.2")
}
