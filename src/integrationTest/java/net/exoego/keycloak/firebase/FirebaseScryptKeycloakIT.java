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

import com.fasterxml.jackson.databind.ObjectMapper;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.PartialImportRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FirebaseScryptKeycloakIT {

    // Project parameters and accounts from https://github.com/firebase/scrypt (tests/01-known-value.sh and README.md).
    private static final String SIGNER_KEY = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
    private static final String SALT = "42xEC+ixf3L2lw==";
    private static final String HUNTER2_HASH = "70k8Vg5B3/OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A==";
    // hunter2 with an empty salt, made with the firebase/scrypt tool.
    private static final String EMPTY_SALT_HASH = "PIIeWiyHb2as+yzOFiCZB/lbDaJL80Lx7o5PsN+aT1qZOIKEIVuW/tih8Ka73fKcp5MKpTr3q5RznpeWRFgflA==";
    private static final String USER1_HASH = "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

    private static final String REALM = "firebase";
    private static final String FILE_REALM = "firebase-file";
    private static final String CLIENT_ID = "test-cli";
    private static final String CLIENT_SECRET = "test-secret";
    private static final ObjectMapper JSON = new ObjectMapper();

    private static KeycloakContainer keycloak;
    private static Keycloak admin;

    private final HttpClient http = HttpClient.newHttpClient();

    @BeforeAll
    static void startKeycloak() {
        keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:" + System.getProperty("keycloak.version"))
                .withProviderLibsFrom(List.of(new File(System.getProperty("provider.jar"))))
                .withRealmImportFile("/firebase-file-realm.json")
                .withEnv("KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__SIGNER_KEY", SIGNER_KEY)
                .withEnv("KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__SALT_SEPARATOR", "Bw==")
                .withEnv("KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__ROUNDS", "8")
                .withEnv("KC_SPI_PASSWORD_HASHING__FIREBASE_SCRYPT__MEM_COST", "14");
        keycloak.start();
        admin = keycloak.getKeycloakAdminClient();

        RealmRepresentation realm = new RealmRepresentation();
        realm.setRealm(REALM);
        realm.setEnabled(true);
        admin.realms().create(realm);

        ClientRepresentation client = new ClientRepresentation();
        client.setClientId(CLIENT_ID);
        client.setPublicClient(false);
        client.setSecret(CLIENT_SECRET);
        client.setDirectAccessGrantsEnabled(true);
        client.setStandardFlowEnabled(false);
        try (Response response = admin.realm(REALM).clients().create(client)) {
            assertEquals(201, response.getStatus());
        }
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
        try (Response response = admin.realm(REALM).users().create(firebaseUser("empty-salt-user", EMPTY_SALT_HASH, ""))) {
            assertEquals(201, response.getStatus());
        }
        assertMigratesOnFirstLogin(REALM, "empty-salt-user", "hunter2");
    }

    // Fail closed with a clear warning, not a server error or a silent "wrong password".
    // Keycloak itself decodes the base64url salt to other bytes without an error.
    @ParameterizedTest(name = "{0}")
    @CsvSource({
            "base64url-hash, 70k8Vg5B3_OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A==, 42xEC+ixf3L2lw==",
            "base64url-salt, 70k8Vg5B3/OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A==, -----_8AAQIDBA",
    })
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
        return firebaseUser(username, passwordHash, SALT);
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
