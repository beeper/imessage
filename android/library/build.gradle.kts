import java.io.BufferedReader

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
	id("maven-publish")
}

val gitBranch = System.getenv("GITHUB_REF_NAME") ?: gitCommand("git branch --show-current")

val commitHash = gitCommand("git rev-parse --short HEAD")

fun gitCommand(command: String) =
	Runtime
		.getRuntime()
		.exec(command)
		.let { process ->
			process.waitFor()
			val output = process.inputStream.use {
				it.bufferedReader().use(BufferedReader::readText)
			}
			process.destroy()
			output.trim()
		}

android {
    namespace = "com.beeper.imessage"
    compileSdk = 34

    defaultConfig {
        minSdk = 26
		buildConfigField("String", "GIT_BRANCH", "\"$gitBranch\"")
		buildConfigField("String", "GIT_HASH", "\"$commitHash\"")
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
	buildFeatures {
		buildConfig = true
	}
}

afterEvaluate {
	publishing {
		repositories {
			maven {
				url = uri("https://maven.pkg.github.com/beeper/imessage")
				credentials {
					username = System.getenv("GITHUB_ACTOR")
					password = System.getenv("GITHUB_TOKEN")
				}
			}
		}
		publications {
			create<MavenPublication>("github") {
				from(components["release"])
				groupId = "com.beeper"
				artifactId = "imessage"
				version = "${gitBranch.replace("/", "-")}-$commitHash"
				pom {
					name.set("im-on-and")
					description.set("im-on-and")
					url.set("https://beeper.com")
					scm {
						developerConnection.set("scm:git:ssh://github.com/beeper/imessage.git")
						url.set("https://github.com/beeper/imessage")
					}
				}
			}
		}
	}
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    implementation("com.google.android.material:material:1.9.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}
