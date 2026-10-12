package net.exoego.keycloak.firebase;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
        byte[] hash = FirebaseScrypt.hash(
                v.password().getBytes(StandardCharsets.UTF_8),
                b64(v.salt()), b64(v.saltSeparator()), b64(v.signerKey()), v.rounds(), v.memCost());

        assertEquals(v.hash(), Base64.getEncoder().encodeToString(hash));
    }

    private static byte[] b64(String s) {
        return Base64.getDecoder().decode(s);
    }
}
