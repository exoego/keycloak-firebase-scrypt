# keycloak-firebase-scrypt

A Keycloak password hash provider for users moved from Firebase Authentication.

Firebase hashes passwords with its own variant of scrypt. With this provider, Keycloak can verify those hashes,
so users keep their Firebase passwords after the move.
On the first successful login, Keycloak hashes the password again with the realm's algorithm (argon2 by default).

Status: not released yet. The coordinates below are for the first release.

## Compatibility

| keycloak-firebase-scrypt | Keycloak | Java |
|---|---|---|
| 0.1.x | 26.8 | 17, 21, 25 |

- The provider is off in FIPS mode, like the built-in argon2 provider. Both use the non-FIPS BouncyCastle API.
- Keycloak marks the password hashing SPI as internal. It may change in any Keycloak release, and Keycloak logs a warning
  when it loads this provider. The integration tests run the provider in a real Keycloak to catch such changes.

## Install

The artifact is `net.exoego:keycloak-firebase-scrypt` on Maven Central.

Maven:

```xml
<dependency>
  <groupId>net.exoego</groupId>
  <artifactId>keycloak-firebase-scrypt</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle:

```kotlin
implementation("net.exoego:keycloak-firebase-scrypt:0.1.0")
```

The jar has no dependencies of its own. Put it in `/opt/keycloak/providers/` and run `kc.sh build`.
For example, in a container image:

```dockerfile
FROM quay.io/keycloak/keycloak:26.8.0 AS builder
ADD --chown=keycloak:keycloak https://repo1.maven.org/maven2/net/exoego/keycloak-firebase-scrypt/0.1.0/keycloak-firebase-scrypt-0.1.0.jar /opt/keycloak/providers/
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:26.8.0
COPY --from=builder /opt/keycloak/ /opt/keycloak/
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
```

## Configure

Copy the hash parameters of your Firebase project from the Firebase console:
Authentication, Users, the menu above the user list, "Password hash parameters".

| Option | Firebase parameter |
|---|---|
| `signer-key` | `base64_signer_key` |
| `salt-separator` | `base64_salt_separator` |
| `rounds` | `rounds` |
| `mem-cost` | `mem_cost` |

Pass them as environment variables:

```sh
KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__SIGNER_KEY=...
KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__SALT_SEPARATOR=...
KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__ROUNDS=8
KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__MEM_COST=14
```

or as options, such as `--spi-password-hashing--firebase-scrypt--signer-key=...`.

- The signer key is a secret of the Firebase project. Keep it in a secret store.
  Prefer the environment variable, because other users of the host can see command line options.
- Keycloak does not start if an option is missing or invalid. Without them, no imported user could log in.
  `rounds` must be 1 to 8 and `mem-cost` 1 to 14, the same limits as the Firebase Admin SDK.
- One Keycloak takes the parameters of one Firebase project.

## Import users

Give each user a password credential like this:

```json
{
  "type": "password",
  "userLabel": "firebase-import",
  "credentialData": "{\"hashIterations\":8,\"algorithm\":\"firebase-scrypt\",\"algorithmData\":{}}",
  "secretData": "{\"value\":\"<passwordHash>\",\"salt\":\"<salt>\",\"algorithmData\":{}}"
}
```

- `<passwordHash>` and `<salt>` are the values of the user in the Firebase export.
- Use standard base64. Some Firebase APIs return base64url, with `-` and `_`. Convert those values first.
- The provider ignores `hashIterations` and uses the `rounds` option.
- If a credential is broken, the login fails and Keycloak logs a warning with `ModelException: firebase-scrypt: <reason>`.
  For example, the hash or the salt is missing or is not standard base64, or the hash has another length than the signer key.
- The same credential works in `POST /admin/realms/{realm}/users`, in `POST /admin/realms/{realm}/partialImport`,
  and in a realm import file.

## How it works

- The provider only verifies hashes. It cannot create them.
  Do not choose `firebase-scrypt` as the hashing algorithm of a realm password policy.
  The provider never becomes the default algorithm.
- After a successful login, Keycloak sees that the stored algorithm differs from the realm's algorithm and replaces the hash.
  The credential keeps its ID and label.
- Users who never log in keep the Firebase hash. Keep the provider until you have reset their passwords or removed them.
- A password that contains a NUL character never matches. Otherwise `pw` followed by NUL would match `pw`,
  because HMAC pads short keys with zero bytes.

## Build and test

```sh
./gradlew check
```

`check` also runs the integration tests. They start Keycloak with Testcontainers, so they need Docker.
They import users with the Firebase test vectors, log in, and check that the hash changes to argon2.

The unit tests also use `src/test/resources/firebase-scrypt-vectors/reference.csv`, made with the
[firebase/scrypt](https://github.com/firebase/scrypt) tool. It covers non-ASCII passwords, long passwords and other parameters.

## Release

Publish a GitHub release with a tag like `v0.1.0`. The `publish.yml` workflow then publishes to Maven Central.
It needs the secrets `SONATYPE_USERNAME`, `SONATYPE_PASSWORD`, `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE`.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.

The hash function is a Java port of the modified scrypt in [firebase/scrypt](https://github.com/firebase/scrypt),
and the test vectors come from that repository. Its license is in `licenses/firebase-scrypt.txt`.
