package net.exoego.keycloak.firebase;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test vectors from https://github.com/firebase/scrypt (tests/ and README.md).
 * All of them use salt separator Bw==, rounds 8 and mem_cost 14.
 */
class FirebaseScryptTest {

    static final String KEY_01 = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
    static final String KEY_02 = "NkZlKPkYEFfnbh1nYTfLsbqQnQ6jyRV4itK7iUD+hjO96tsAYhBG40BVS3AuJyiwHinqc5RR3oA+lppOXPNRmw==";
    static final String KEY_03 = "U01Ba7WbeBZyY/HjvbEp+N9KkB2h/oF7uSSbBSCj803usz1GV7YIhM+LlusLiU+t3qbz8hh5PLOUSekExEY04w==";
    static final String SALT_SEPARATOR = "Bw==";
    static final int ROUNDS = 8;
    static final int MEM_COST = 14;

    static final String HUNTER2_SALT = "42xEC+ixf3L2lw==";
    static final String HUNTER2_HASH = "70k8Vg5B3/OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A==";

    record Vector(String source, String signerKey, String password, String hash, String salt) {
        @Override
        public String toString() {
            return source + " [" + password + "]";
        }
    }

    static List<Vector> vectors() {
        List<Vector> vectors = new ArrayList<>();
        vectors.add(new Vector("01-known-value.sh", KEY_01, "hunter2", HUNTER2_HASH, HUNTER2_SALT));
        vectors.add(new Vector("README.md", KEY_01, "user1password",
                "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==", HUNTER2_SALT));
        vectors.addAll(load("02-more-values-passwords.good", KEY_02));
        vectors.addAll(load("03-more-values-different-key-passwords.good", KEY_03));
        return vectors;
    }

    @Test
    void loadsAllOfficialVectors() {
        assertEquals(2 + 13 + 13, vectors().size());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void matchesOfficialVector(Vector v) {
        byte[] hash = FirebaseScrypt.hash(
                v.password().getBytes(StandardCharsets.UTF_8),
                b64(v.salt()), b64(SALT_SEPARATOR), b64(v.signerKey()), ROUNDS, MEM_COST);

        assertEquals(v.hash(), Base64.getEncoder().encodeToString(hash));
    }

    static byte[] b64(String s) {
        return Base64.getDecoder().decode(s);
    }

    // Each line is "password,hash,salt", as read by bulk_password_test in tests/shared_test_functions.sh.
    private static List<Vector> load(String file, String signerKey) {
        List<Vector> vectors = new ArrayList<>();
        try (InputStream in = FirebaseScryptTest.class.getResourceAsStream("/firebase-scrypt-vectors/" + file);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) {
                    continue;
                }
                String[] parts = line.split(",", -1);
                assertEquals(3, parts.length, line);
                vectors.add(new Vector(file, signerKey, parts[0], parts[1], parts[2]));
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return vectors;
    }
}
