plugins { id("com.android.application") }
android {
    namespace = "com.rubiqueq.saf"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.rubiqueq.saf.queue"
        minSdk = 26
        targetSdk = 35
        versionCode = 4
        versionName = "1.2.0-rc2"
    }
    buildTypes { release { isMinifyEnabled = false } }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}
