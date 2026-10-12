package net.exoego.keycloak.firebase;

import java.io.File;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.PartialImportRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.images.builder.Transferable;

import static net.exoego.keycloak.firebase.FirebaseScryptVectors.BASE64URL_SALT;
import static net.exoego.keycloak.firebase.FirebaseScryptVectors.HUNTER2_HASH;
import static net.exoego.keycloak.firebase.FirebaseScryptVectors.HUNTER2_SALT;
import static net.exoego.keycloak.firebase.FirebaseScryptVectors.KEY_01;
import static net.exoego.keycloak.firebase.FirebaseScryptVectors.MEM_COST;
import static net.exoego.keycloak.firebase.FirebaseScryptVectors.ROUNDS;
import static net.exoego.keycloak.firebase.FirebaseScryptVectors.SALT_SEPARATOR;
import static net.exoego.keycloak.firebase.FirebaseScryptVectors.USER1_HASH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FirebaseScryptKeycloakIT {

    private static final String REALM = "firebase";
    private static final String FILE_REALM = "firebase-file";
    private static final String CLIENT_ID = "test-cli";
    private static final String CLIENT_SECRET = "test-secret";
    private static final ObjectMapper JSON = new ObjectMapper();

    private static KeycloakContainer keycloak;
    private static Keycloak admin;

    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    static void startKeycloak() throws Exception {
        RealmRepresentation fileRealm = realm(FILE_REALM);
        fileRealm.setUsers(List.of(firebaseUser("file-user", USER1_HASH)));

        keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version"))
                .withProviderLibsFrom(List.of(new File(System.getProperty("provider.jar"))))
                .withCopyToContainer(Transferable.of(JSON.writeValueAsString(fileRealm)),
                        "/opt/keycloak/data/import/" + FILE_REALM + ".json")
                .withEnv("KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__SIGNER_KEY", KEY_01)
                .withEnv("KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__SALT_SEPARATOR", SALT_SEPARATOR)
                .withEnv("KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__ROUNDS", String.valueOf(ROUNDS))
                .withEnv("KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__MEM_COST", String.valueOf(MEM_COST));
        keycloak.start();
        admin = keycloak.getKeycloakAdminClient();
        admin.realms().create(realm(REALM));
    }

    private static RealmRepresentation realm(String name) {
        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(CLIENT_ID);
        client.setPublicClient(false);
        client.setSecret(CLIENT_SECRET);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(false);

        RealmRepresentation realm = new RealmRepresentation();
        realm.setRealm(name);
        realm.setEnabled(true);
        realm.setClients(List.of(client));
        return realm;
    }

    @AfterAll
    static void stopKeycloak() {
        if (admin != null) {
            admin.close();
        }
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    @Test
    void userImportedThroughUsersApiMigratesOnFirstLogin() throws Exception {
        try (Response response = admin.realm(REALM).users().create(firebaseUser("hunter2-user", HUNTER2_HASH))) {
            assertEquals(201, response.getStatus());
        }
        assertMigratesOnFirstLogin(REALM, "hunter2-user", "hunter2");
    }

    @Test
    void userImportedThroughPartialImportMigratesOnFirstLogin() throws Exception {
        PartialImportRepresentation partialImport = new PartialImportRepresentation();
        partialImport.setIfResourceExists("FAIL");
        partialImport.setUsers(List.of(firebaseUser("user1", USER1_HASH)));
        try (Response response = admin.realm(REALM).partialImport(partialImport)) {
            assertEquals(200, response.getStatus());
            assertEquals(1, JSON.readTree(response.readEntity(String.class)).get("added").asInt());
        }
        assertMigratesOnFirstLogin(REALM, "user1", "user1password");
    }

    @Test
    void userImportedThroughRealmImportFileMigratesOnFirstLogin() throws Exception {
        assertMigratesOnFirstLogin(FILE_REALM, "file-user", "user1password");
    }

    @Test
    void userWithEmptySaltMigratesOnFirstLogin() throws Exception {
        try (Response response = admin.realm(REALM).users().create(firebaseUser("empty-salt-user", FirebaseScryptVectors.emptySalt().hash(), ""))) {
            assertEquals(201, response.getStatus());
        }
        assertMigratesOnFirstLogin(REALM, "empty-salt-user", "hunter2");
    }

    // Fail closed with a clear warning, not a server error or a silent "wrong password".
    // Keycloak itself decodes the base64url salt to other bytes without an error.
    static Stream<Arguments> malformedCredentials() {
        return Stream.of(
                Arguments.of("base64url-hash", HUNTER2_HASH.replace('+', '-').replace('/', '_'), HUNTER2_SALT),
                Arguments.of("base64url-salt", HUNTER2_HASH, BASE64URL_SALT));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("malformedCredentials")
    void malformedCredentialDeniesLoginWithWarning(String username, String hash, String salt) throws Exception {
        try (Response response = admin.realm(REALM).users().create(firebaseUser(username, hash, salt))) {
            assertEquals(201, response.getStatus());
        }
        String userId = admin.realm(REALM).users().searchByUsername(username, true).get(0).getId();
        int logStart = keycloak.getLogs().length();

        assertInvalidCredentials(passwordGrant(REALM, username, "hunter2"));

        assertEquals("firebase-scrypt", algorithm(passwordCredential(REALM, userId)));
        String logs = keycloak.getLogs().substring(logStart);
        assertTrue(logs.contains("Error when validating user password"), logs);
        assertTrue(logs.contains("org.keycloak.models.ModelException: firebase-scrypt"), logs);
        assertFalse(logs.contains(hash), logs);
        assertFalse(logs.contains(salt), logs);
    }

    private void assertMigratesOnFirstLogin(String realm, String username, String password) throws Exception {
        String userId = admin.realm(realm).users().searchByUsername(username, true).get(0).getId();
        CredentialRepresentation imported = passwordCredential(realm, userId);
        assertEquals("firebase-scrypt", algorithm(imported));
        int logStart = keycloak.getLogs().length();

        assertInvalidCredentials(passwordGrant(realm, username, password + "x"));
        assertEquals("firebase-scrypt", algorithm(passwordCredential(realm, userId)));

        assertEquals(200, passwordGrant(realm, username, password).statusCode());
        CredentialRepresentation rehashed = awaitAlgorithm(realm, userId, "argon2");
        assertEquals(imported.getId(), rehashed.getId());
        assertEquals(imported.getUserLabel(), rehashed.getUserLabel());

        assertEquals(200, passwordGrant(realm, username, password).statusCode());
        assertInvalidCredentials(passwordGrant(realm, username, password + "x"));

        String logs = keycloak.getLogs().substring(logStart);
        assertFalse(logs.contains("Error when validating user password"), logs);
    }

    // The same credentialData and secretData strings work with the Admin API, partialImport and a realm import file.
    private static UserRepresentation firebaseUser(String username, String passwordHash) {
        return firebaseUser(username, passwordHash, HUNTER2_SALT);
    }

    private static UserRepresentation firebaseUser(String username, String passwordHash, String salt) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setUserLabel("firebase-import");
        credential.setCredentialData("{\"hashIterations\":8,\"algorithm\":\"firebase-scrypt\",\"algorithmData\":{}}");
        credential.setSecretData("{\"value\":\"" + passwordHash + "\",\"salt\":\"" + salt + "\",\"algorithmData\":{}}");

        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEmail(username + "@example.com");
        user.setEmailVerified(true);
        user.setFirstName("Firebase");
        user.setLastName("User");
        user.setEnabled(true);
        user.setCredentials(List.of(credential));
        return user;
    }

    private static CredentialRepresentation passwordCredential(String realm, String userId) {
        List<CredentialRepresentation> passwords = admin.realm(realm).users().get(userId).credentials().stream()
                .filter(c -> CredentialRepresentation.PASSWORD.equals(c.getType()))
                .toList();
        assertEquals(1, passwords.size());
        return passwords.get(0);
    }

    private static String algorithm(CredentialRepresentation credential) throws Exception {
        return JSON.readTree(credential.getCredentialData()).get("algorithm").asText();
    }

    // Keycloak rehashes after the login transaction commits, so the new hash shows up a little later.
    private static CredentialRepresentation awaitAlgorithm(String realm, String userId, String expected) throws Exception {
        Instant deadline = Instant.now().plus(Duration.ofSeconds(15));
        CredentialRepresentation credential = passwordCredential(realm, userId);
        while (!expected.equals(algorithm(credential)) && Instant.now().isBefore(deadline)) {
            Thread.sleep(500);
            credential = passwordCredential(realm, userId);
        }
        assertEquals(expected, algorithm(credential));
        return credential;
    }

    private HttpResponse<String> passwordGrant(String realm, String username, String password) throws Exception {
        Map<String, String> form = Map.of(
                "grant_type", "password",
                "client_id", CLIENT_ID,
                "client_secret", CLIENT_SECRET,
                "username", username,
                "password", password,
                "scope", "openid");
        String body = form.entrySet().stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create(keycloak.getAuthServerUrl() + "/realms/" + realm + "/protocol/openid-connect/token"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    // A wrong password on the direct grant gives 400 invalid_grant, not 401.
    private static void assertInvalidCredentials(HttpResponse<String> response) throws Exception {
        assertEquals(400, response.statusCode(), response.body());
        var error = JSON.readTree(response.body());
        assertEquals("invalid_grant", error.get("error").asText());
        assertEquals("Invalid user credentials", error.get("error_description").asText());
    }
}
