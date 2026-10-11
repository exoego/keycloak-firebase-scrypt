plugins {
    `java-library`
    `maven-publish`
    signing
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
}

group = "net.exoego"
version = System.getenv("RELEASE_VERSION") ?: "0.1.0-SNAPSHOT"

val keycloakVersion = "26.8.0"
val junitVersion = "6.1.3"

// Keycloak loads these from its own lib directory, so the provider jar must not bundle them.
// The versions match /opt/keycloak/lib of quay.io/keycloak/keycloak:26.8.0.
val keycloakProvided = listOf(
    "org.keycloak:keycloak-core:$keycloakVersion",
    "org.keycloak:keycloak-common:$keycloakVersion",
    "org.keycloak:keycloak-server-spi:$keycloakVersion",
    "org.keycloak:keycloak-server-spi-private:$keycloakVersion",
    "org.bouncycastle:bcprov-jdk18on:1.86",
    "org.jboss.logging:jboss-logging:3.6.3.Final",
)

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    withJavadocJar()
    withSourcesJar()
}

repositories {
    mavenCentral()
}

dependencies {
    keycloakProvided.forEach {
        compileOnly(it)
        testImplementation(it)
    }
}

tasks.withType<Jar>().configureEach {
    from(files("LICENSE", "NOTICE")) {
        into("META-INF")
    }
    from("licenses") {
        into("META-INF/licenses")
    }
}

testing {
    suites {
        named<JvmTestSuite>("test") {
            useJUnitJupiter(junitVersion)
        }

        // Runs the built jar in a real Keycloak container. Needs Docker.
        register<JvmTestSuite>("integrationTest") {
            useJUnitJupiter(junitVersion)
            dependencies {
                implementation("com.github.dasniko:testcontainers-keycloak:4.4.0")
                runtimeOnly("org.slf4j:slf4j-simple:2.0.17")
            }
            targets.all {
                testTask.configure {
                    dependsOn(tasks.jar)
                    systemProperty("keycloak.version", keycloakVersion)
                    systemProperty("provider.jar", tasks.jar.get().archiveFile.get().asFile.absolutePath)
                    shouldRunAfter(tasks.test)
                }
            }
        }
    }
}

// The jar targets Java 21, but CI also runs the tests on newer LTS releases with -PtestJavaVersion.
val testJavaVersion = providers.gradleProperty("testJavaVersion").orElse("21")
tasks.withType<Test>().configureEach {
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(testJavaVersion.map { JavaLanguageVersion.of(it) })
    })
}

tasks.check {
    dependsOn(testing.suites.named("integrationTest"))
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://ossrh-staging-api.central.sonatype.com/service/local/"))
            snapshotRepositoryUrl.set(uri("https://central.sonatype.com/repository/maven-snapshots/"))
            username.set(System.getenv("SONATYPE_USERNAME"))
            password.set(System.getenv("SONATYPE_PASSWORD"))
        }
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])

            pom {
                name.set("keycloak-firebase-scrypt")
                description.set("Keycloak password hash provider that verifies password hashes exported from Firebase Authentication")
                url.set("https://github.com/exoego/keycloak-firebase-scrypt")

                licenses {
                    license {
                        name.set("Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }

                developers {
                    developer {
                        id.set("exoego")
                        name.set("TATSUNO Yasuhiro")
                        email.set("ytatsuno.jp@gmail.com")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/exoego/keycloak-firebase-scrypt.git")
                    developerConnection.set("scm:git:ssh://github.com:exoego/keycloak-firebase-scrypt.git")
                    url.set("https://github.com/exoego/keycloak-firebase-scrypt")
                }
            }
        }
    }
}

signing {
    val signingKey = System.getenv("GPG_PRIVATE_KEY")
    val signingPassword = System.getenv("GPG_PASSPHRASE")
    if (signingKey != null && signingPassword != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications["maven"])
    }
}
