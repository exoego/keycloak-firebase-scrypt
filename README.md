# Verify-only Firebase scrypt provider for Keycloak
[![Maven Central](https://img.shields.io/maven-central/v/net.exoego/keycloak-firebase-scrypt)](https://central.sonatype.com/artifact/net.exoego/keycloak-firebase-scrypt)
[![codecov](https://codecov.io/gh/exoego/keycloak-firebase-scrypt/graph/badge.svg?token=a0EhBN7vkq)](https://codecov.io/gh/exoego/keycloak-firebase-scrypt)

A Keycloak password hash provider for users moved from Firebase Authentication.

Firebase hashes passwords with its own variant of scrypt. With this provider, Keycloak can verify those hashes,
so users keep their Firebase passwords after the move.
On the first successful login, Keycloak replaces the hash with one in the realm's algorithm.

## Compatibility

| keycloak-firebase-scrypt | Keycloak |
|---|---|
| 1.0.x | 24.0.5, 25.0.6, 26.8 |

- The provider is off in FIPS mode, like the built-in argon2 provider. scrypt is not a FIPS approved algorithm.
- Keycloak marks the password hashing SPI as internal, so `kc.sh build` logs the warning `KC-SERVICES0047`.
  The SPI may change in any Keycloak release. The integration tests run the provider in a real Keycloak to catch such changes.

## Install

Download the jar of the latest version from [Maven Central](https://repo1.maven.org/maven2/net/exoego/keycloak-firebase-scrypt/),
put it in `/opt/keycloak/providers/` and run `kc.sh build`.
The jar has no dependencies of its own. For example, in a container image:

```dockerfile
FROM quay.io/keycloak/keycloak:26.8.0 AS builder
ADD --chown=keycloak:keycloak https://repo1.maven.org/maven2/net/exoego/keycloak-firebase-scrypt/1.0.0/keycloak-firebase-scrypt-1.0.0.jar /opt/keycloak/providers/
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

The same options work on the command line and in `keycloak.conf`, as `spi-password-hashing--firebase-scrypt--signer-key` and so on.
Keycloak 26.2 and earlier do not know the double separator. Use a single one there,
such as `KC_SPI_PASSWORD_HASHING_FIREBASE_SCRYPT_SIGNER_KEY`.

- The signer key is a secret of the Firebase project. Keep it in a secret store.
  Prefer the environment variable, because other users of the host can see command line options.
  If you use `keycloak.conf`, let only the Keycloak user read it.
- Keycloak does not start if an option is missing or invalid. Without them, no imported user could log in.
  `rounds` must be 1 to 8 and `mem-cost` 1 to 14, the same limits as the Firebase Admin SDK.
- One Keycloak takes the parameters of one Firebase project.

When Keycloak starts with valid options, it logs this line:

```
INFO  [net.exoego.keycloak.firebase.FirebaseScryptPasswordHashProviderFactory] (main) firebase-scrypt enabled: rounds=8, mem-cost=14, signer key 64 bytes
```

Check that `rounds`, `mem-cost` and the length of the signer key match your Firebase project.

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
  Keep `"salt":""` for a user without a salt. A missing `salt` field counts as a broken credential.
- Use standard base64. Some Firebase APIs return base64url, with `-` and `_`. Convert those values first.
  Keycloak 24 and 25 refuse a salt that is not standard base64 at import with a server error, and do not create the user.
- The provider ignores `hashIterations` and uses the `rounds` option.
- If a credential is broken, the login fails and Keycloak logs a warning with `ModelException: firebase-scrypt: <reason>`.
  For example, the hash or the salt is missing or is not standard base64, or the hash has another length than the signer key.
- The same credential works in `POST /admin/realms/{realm}/users`, in `POST /admin/realms/{realm}/partialImport`,
  and in a realm import file.

## How it works

- The provider only verifies hashes. Do not choose `firebase-scrypt` as the algorithm of a realm password policy.
- The credential keeps its ID and label after Keycloak replaces the hash.
- Users who never log in keep the Firebase hash. Keep the provider until you have reset their passwords or removed them.
- One verification needs `128 * rounds * 2^mem-cost` bytes of memory, 16 MiB with the Firebase defaults.
  The provider keeps up to one such buffer per CPU and reuses it.

## Build and test

```sh
./gradlew check
```

`check` also runs the integration tests. They start Keycloak with Testcontainers, so they need Docker.
Pass `-PtestKeycloakVersion=25.0.6` to test another Keycloak version.

## Release

Publish a GitHub release with a tag like `v1.0.0`. The `publish.yml` workflow then publishes to Maven Central
with the secrets of the `release` environment.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.

The hash function is a Java port of the modified scrypt in [firebase/scrypt](https://github.com/firebase/scrypt),
and the test vectors come from that repository. Its license is in `licenses/firebase-scrypt.txt`.
