package net.exoego.keycloak.firebase;

import java.text.Normalizer;
import java.util.Arrays;
import java.util.Base64;
import java.util.stream.Stream;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.ModelException;
import org.keycloak.models.credential.PasswordCredentialModel;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import static net.exoego.keycloak.firebase.FirebaseScryptTest.HUNTER2_HASH;
import static net.exoego.keycloak.firebase.FirebaseScryptTest.HUNTER2_SALT;
import static net.exoego.keycloak.firebase.FirebaseScryptTest.referenceVector;
import static net.exoego.keycloak.firebase.TestFixtures.imported;
import static net.exoego.keycloak.firebase.TestFixtures.options;
import static net.exoego.keycloak.firebase.TestFixtures.provider;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FirebaseScryptPasswordHashProviderTest {

    private static final FirebaseScryptTest.Vector UTF8 = referenceVector("pässwörd");

    private final PasswordHashProvider provider = provider(options());
    private final PasswordCredentialModel hunter2 = imported(HUNTER2_HASH, HUNTER2_SALT);

    @Test
    void acceptsCorrectPassword() {
        assertTrue(provider.verify("hunter2", hunter2));
    }

    @ParameterizedTest(name = "[{0}]")
    @ValueSource(strings = {"hunter3", "Hunter2", "hunter", "hunter22", "hunter2 ", " hunter2", "hunter2\n", "hunter2\u0000", ""})
    void rejectsWrongPassword(String password) {
        assertFalse(provider.verify(password, hunter2));
    }

    @Test
    void rejectsNullPassword() {
        assertFalse(provider.verify(null, hunter2));
    }

    @Test
    void hashesPasswordAsUtf8() {
        assertTrue(provider.verify(UTF8.password(), imported(UTF8.hash(), UTF8.salt())));
    }

    // Firebase hashes the bytes it receives. Keycloak must not accept another Unicode form of the same text.
    @Test
    void doesNotNormalizeUnicode() {
        String decomposed = Normalizer.normalize(UTF8.password(), Normalizer.Form.NFD);
        assertNotEquals(UTF8.password(), decomposed);
        assertFalse(provider.verify(decomposed, imported(UTF8.hash(), UTF8.salt())));
    }

    @ParameterizedTest(name = "{0}={1}")
    @CsvSource({
            "signer-key," + FirebaseScryptTest.KEY_02,
            "salt-separator,AAECAwQFBgc=",
            "rounds,7",
            "mem-cost,13",
    })
    void rejectsWhenProjectParameterDiffers(String option, String value) {
        assertFalse(provider(options(option, value)).verify("hunter2", hunter2));
    }

    @Test
    void rejectsHashOfAnotherSalt() {
        assertFalse(provider.verify("hunter2", imported(HUNTER2_HASH, UTF8.salt())));
    }

    static Stream<Arguments> malformedCredentials() {
        byte[] hash = Base64.getDecoder().decode(HUNTER2_HASH);
        Base64.Encoder encoder = Base64.getEncoder();
        return Stream.of(
                Arguments.of("base64url hash", HUNTER2_HASH.replace('+', '-').replace('/', '_'), HUNTER2_SALT),
                Arguments.of("hash not base64", "not base64!", HUNTER2_SALT),
                Arguments.of("truncated hash", encoder.encodeToString(Arrays.copyOf(hash, hash.length - 1)), HUNTER2_SALT),
                Arguments.of("extended hash", encoder.encodeToString(Arrays.copyOf(hash, hash.length + 1)), HUNTER2_SALT),
                Arguments.of("empty hash", "", HUNTER2_SALT),
                Arguments.of("no hash", null, HUNTER2_SALT),
                Arguments.of("empty salt", HUNTER2_HASH, ""),
                Arguments.of("no salt", HUNTER2_HASH, null));
    }

    // A broken import must show up in the log, instead of looking like a wrong password.
    @ParameterizedTest(name = "{0}")
    @MethodSource("malformedCredentials")
    void failsLoudlyOnMalformedCredential(String name, String hash, String salt) {
        PasswordCredentialModel credential = imported(hash, salt);
        ModelException e = assertThrows(ModelException.class, () -> provider.verify("hunter2", credential));
        assertTrue(e.getMessage().contains(FirebaseScryptPasswordHashProviderFactory.ID), e.getMessage());
        for (String secret : new String[] {hash, salt}) {
            if (secret != null && !secret.isEmpty()) {
                assertFalse(e.getMessage().contains(secret), e.getMessage());
            }
        }
    }

    @Test
    void refusesToCreateHashes() {
        assertThrows(ModelException.class, () -> provider.encodedCredential("hunter2", -1));
        assertThrows(ModelException.class, () -> provider.encode("hunter2", -1));
    }

    // Keycloak calls policyCheck only on the realm's algorithm. It reaches this provider only in a misconfigured realm.
    @Test
    void neverReportsCredentialAsUpToDate() {
        assertFalse(provider.policyCheck(null, hunter2));
    }
}
