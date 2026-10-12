package net.exoego.keycloak.firebase;

import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static net.exoego.keycloak.firebase.FirebaseScryptPasswordHashProviderFactory.MEM_COST;
import static net.exoego.keycloak.firebase.FirebaseScryptPasswordHashProviderFactory.ROUNDS;
import static net.exoego.keycloak.firebase.FirebaseScryptPasswordHashProviderFactory.SALT_SEPARATOR;
import static net.exoego.keycloak.firebase.FirebaseScryptPasswordHashProviderFactory.SIGNER_KEY;
import static net.exoego.keycloak.firebase.FirebaseScryptTest.HUNTER2_HASH;
import static net.exoego.keycloak.firebase.FirebaseScryptTest.HUNTER2_SALT;
import static net.exoego.keycloak.firebase.FirebaseScryptTest.KEY_01;
import static net.exoego.keycloak.firebase.TestFixtures.imported;
import static net.exoego.keycloak.firebase.TestFixtures.options;
import static net.exoego.keycloak.firebase.TestFixtures.provider;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FirebaseScryptPasswordHashProviderFactoryTest {

    @ParameterizedTest(name = "{0}={1}")
    @CsvSource({"rounds,1", "rounds,8", "mem-cost,1", "mem-cost,14"})
    void acceptsCostWithinFirebaseLimits(String option, String value) {
        assertDoesNotThrow(() -> provider(options(option, value)));
    }

    // Values often come from files or secret stores with a trailing newline.
    @Test
    void trimsSurroundingWhitespace() {
        Map<String, String> options = options();
        options.replaceAll((option, value) -> " \t" + value + "\n");

        assertTrue(provider(options).verify("hunter2", imported(HUNTER2_HASH, HUNTER2_SALT)));
    }

    static Stream<Arguments> missingOptions() {
        return Stream.of(SIGNER_KEY, SALT_SEPARATOR, ROUNDS, MEM_COST)
                .flatMap(option -> Stream.of(
                        Arguments.of(option, null),
                        Arguments.of(option, ""),
                        Arguments.of(option, " \n")));
    }

    @ParameterizedTest(name = "{0}=[{1}]")
    @MethodSource("missingOptions")
    void requiresEveryOption(String option, String value) {
        assertFailsNaming(option, options(option, value));
    }

    @ParameterizedTest(name = "{0}=[{1}]")
    @CsvSource(delimiter = '|', value = {
            "signer-key|not base64!",
            "signer-key|" + "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA=-",
            "signer-key|jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH 0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==",
            "salt-separator|-w==",
            "salt-separator|B w==",
    })
    void rejectsValueThatIsNotStandardBase64(String option, String value) {
        assertFailsNaming(option, options(option, value));
    }

    @ParameterizedTest(name = "{0}=[{1}]")
    @CsvSource({
            "rounds,eight", "rounds,8.0", "rounds,0x8", "rounds,2147483648",
            "mem-cost,fourteen", "mem-cost,14.0", "mem-cost,0xe", "mem-cost,2147483648",
    })
    void rejectsCostThatIsNotAnInteger(String option, String value) {
        assertFailsNaming(option, options(option, value));
    }

    @ParameterizedTest(name = "{0}={1}")
    @CsvSource({"rounds,0", "rounds,-1", "rounds,9", "mem-cost,0", "mem-cost,-1", "mem-cost,15", "mem-cost,30"})
    void rejectsCostOutsideFirebaseLimits(String option, String value) {
        assertFailsNaming(option, options(option, value));
    }

    @Test
    void errorDoesNotLeakSignerKey() {
        String almostKey = "-" + KEY_01.substring(1);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> provider(options(SIGNER_KEY, almostKey)));
        for (Throwable t = e; t != null; t = t.getCause()) {
            assertFalse(String.valueOf(t.getMessage()).contains(almostKey), t.toString());
            assertFalse(String.valueOf(t.getMessage()).contains(KEY_01.substring(0, 16)), t.toString());
        }
    }

    // Keycloak must not start with a broken configuration. Otherwise every imported user fails to log in.
    private static void assertFailsNaming(String option, Map<String, String> options) {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> provider(options));
        assertTrue(e.getMessage().contains(option), e.getMessage());
    }
}
