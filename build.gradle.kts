plugins {
    `java-library`
    `maven-publish`
    signing
    jacoco
    `java-test-fixtures`
    alias(libs.plugins.nexus.publish)
}

group = "net.exoego"
version = System.getenv("RELEASE_VERSION") ?: "0.1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(21))
    }
    withJavadocJar()
    withSourcesJar()
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

repositories {
    mavenCentral()
}

dependencies {
    compileOnly(platform(libs.keycloak.parent))
    compileOnly(libs.bundles.keycloak.provided)
    testImplementation(platform(libs.keycloak.parent))
    testImplementation(libs.bundles.keycloak.provided)
    testImplementation(libs.bcprov)
}

tasks.withType<Jar>().configureEach {
    from(files("LICENSE", "NOTICE")) {
        into("META-INF")
    }
    from("licenses") {
        into("META-INF/licenses")
    }
}

// An empty value, as from a CI matrix row without it, means the version of the catalog.
val testKeycloakVersion = providers.gradleProperty("testKeycloakVersion")
    .filter { it.isNotBlank() }
    .orElse(libs.versions.keycloak)

testing {
    suites {
        named<JvmTestSuite>("test") {
            useJUnitJupiter(libs.versions.junit)
        }

        // Runs the built jar in a real Keycloak container. Needs Docker.
        register<JvmTestSuite>("integrationTest") {
            useJUnitJupiter(libs.versions.junit)
            dependencies {
                implementation(testFixtures(project()))
                implementation(libs.testcontainers.keycloak)
                runtimeOnly(libs.slf4j.simple)
            }
            targets.all {
                testTask.configure {
                    dependsOn(tasks.jar)
                    systemProperty("keycloak.version", testKeycloakVersion.get())
                    systemProperty("provider.jar", tasks.jar.get().archiveFile.get().asFile.absolutePath)
                    shouldRunAfter(tasks.test)
                }
            }
        }
    }
}

val testJavaVersion = providers.gradleProperty("testJavaVersion").orElse("21")
tasks.withType<Test>().configureEach {
    javaLauncher.set(javaToolchains.launcherFor {
        languageVersion.set(testJavaVersion.map { JavaLanguageVersion.of(it) })
    })
}

tasks.check {
    dependsOn(testing.suites.named("integrationTest"))
}

tasks.jacocoTestReport {
    reports {
        xml.required.set(true)
    }
}

tasks.jacocoTestCoverageVerification {
    violationRules {
        rule {
            for (counter in listOf("INSTRUCTION", "BRANCH")) {
                limit {
                    this.counter = counter
                    minimum = "1.0".toBigDecimal()
                }
            }
        }
    }
}

tasks.check {
    dependsOn(tasks.jacocoTestCoverageVerification)
}

// The javadoc jar goes to Maven Central, so a warning fails the build. check runs it, so a release does not find it first.
tasks.javadoc {
    (options as StandardJavadocDocletOptions).addBooleanOption("Werror", true)
}

tasks.check {
    dependsOn(tasks.javadoc)
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

// Test fixtures are for this build only.
(components["java"] as AdhocComponentWithVariants).apply {
    withVariantsFromConfiguration(configurations["testFixturesApiElements"]) { skip() }
    withVariantsFromConfiguration(configurations["testFixturesRuntimeElements"]) { skip() }
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
