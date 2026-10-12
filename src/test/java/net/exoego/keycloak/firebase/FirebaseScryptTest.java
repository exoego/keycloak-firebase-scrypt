package net.exoego.keycloak.firebase;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FirebaseScryptTest {

    static List<FirebaseScryptVectors.Vector> vectors() {
        return FirebaseScryptVectors.all();
    }

    @Test
    void loadsAllVectors() {
        assertEquals(2 + 13 + 13 + 9, vectors().size());
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void matchesVector(FirebaseScryptVectors.Vector v) {
        assertEquals(v.hash(), hash(v));
    }

    // The vectors differ in rounds and mem_cost, so the pool also drops and replaces buffers under contention.
    @Test
    void matchesVectorsConcurrently() throws Exception {
        List<FirebaseScryptVectors.Vector> vectors = vectors();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<String>> hashes = pool.invokeAll(vectors.stream().map(v -> (Callable<String>) () -> hash(v)).toList());
            for (int i = 0; i < vectors.size(); i++) {
                assertEquals(vectors.get(i).hash(), hashes.get(i).get(), vectors.get(i).toString());
            }
        } finally {
            pool.shutdown();
        }
    }

    private static String hash(FirebaseScryptVectors.Vector v) {
        byte[] hash = FirebaseScrypt.hash(
                v.password().getBytes(StandardCharsets.UTF_8),
                b64(v.salt()), b64(v.saltSeparator()), b64(v.signerKey()), v.rounds(), v.memCost());
        return Base64.getEncoder().encodeToString(hash);
    }

    @Test
    void failsClearlyWithoutTheCipher() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> FirebaseScrypt.encrypt("AES/NONE/NoPadding", new byte[32], new byte[64]));
        assertEquals("AES/NONE/NoPadding is not available", e.getMessage());
        assertInstanceOf(NoSuchAlgorithmException.class, e.getCause());
    }

    private static byte[] b64(String s) {
        return Base64.getDecoder().decode(s);
    }
}
