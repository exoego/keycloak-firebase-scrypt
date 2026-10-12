package net.exoego.keycloak.firebase;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Official test vectors from https://github.com/firebase/scrypt (tests/ and README.md), plus reference.csv.
 * The official ones use salt separator Bw==, rounds 8 and mem_cost 14, and ASCII passwords only.
 */
public final class FirebaseScryptVectors {

    public static final String KEY_01 = "jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==";
    public static final String KEY_02 = "NkZlKPkYEFfnbh1nYTfLsbqQnQ6jyRV4itK7iUD+hjO96tsAYhBG40BVS3AuJyiwHinqc5RR3oA+lppOXPNRmw==";
    public static final String KEY_03 = "U01Ba7WbeBZyY/HjvbEp+N9KkB2h/oF7uSSbBSCj803usz1GV7YIhM+LlusLiU+t3qbz8hh5PLOUSekExEY04w==";
    public static final String SALT_SEPARATOR = "Bw==";
    public static final int ROUNDS = 8;
    public static final int MEM_COST = 14;

    public static final String HUNTER2_SALT = "42xEC+ixf3L2lw==";
    public static final String HUNTER2_HASH = "70k8Vg5B3/OrvJOiqusnasv0dLcBHoDAqJrJr7TRLBfMw4MitWx51YXJYFdGiyMbMeKtWtLf5HiBDcN0SUOm4A==";
    public static final String USER1_HASH = "lSrfV15cpx95/sZS2W9c9Kp6i/LVgQNDNC/qzrCnh1SAyZvqmZqAjTdn3aoItz+VHjoZilo78198JAdRuid5lQ==";

    // Keycloak decodes the salt with the MIME decoder. It drops the "-" and "_" here, and gives other bytes without an error.
    public static final String BASE64URL_SALT = "-----_8AAQIDBA";

    private FirebaseScryptVectors() {
    }

    public record Vector(String source, String signerKey, String password, String hash, String salt,
                         String saltSeparator, int rounds, int memCost) {
        Vector(String source, String signerKey, String password, String hash, String salt) {
            this(source, signerKey, password, hash, salt, SALT_SEPARATOR, ROUNDS, MEM_COST);
        }

        @Override
        public String toString() {
            return source + " [" + password + "] r=" + rounds + " mem_cost=" + memCost + " sep=" + saltSeparator;
        }
    }

    public static List<Vector> all() {
        List<Vector> vectors = new ArrayList<>();
        vectors.add(new Vector("01-known-value.sh", KEY_01, "hunter2", HUNTER2_HASH, HUNTER2_SALT));
        vectors.add(new Vector("README.md", KEY_01, "user1password", USER1_HASH, HUNTER2_SALT));
        vectors.addAll(official("02-more-values-passwords.good", KEY_02));
        vectors.addAll(official("03-more-values-different-key-passwords.good", KEY_03));
        vectors.addAll(reference());
        return vectors;
    }

    public static List<Vector> reference() {
        return read("reference.csv").stream()
                .map(line -> new Vector("reference.csv", KEY_01, line[0], line[1], line[2], line[3],
                        Integer.parseInt(line[4]), Integer.parseInt(line[5])))
                .toList();
    }

    public static Vector reference(String password) {
        return reference().stream().filter(v -> v.password().equals(password)).findFirst().orElseThrow();
    }

    public static Vector emptySalt() {
        return reference().stream().filter(v -> v.salt().isEmpty()).findFirst().orElseThrow();
    }

    private static List<Vector> official(String file, String signerKey) {
        return read(file).stream().map(line -> new Vector(file, signerKey, line[0], line[1], line[2])).toList();
    }

    private static List<String[]> read(String file) {
        List<String[]> lines = new ArrayList<>();
        try (InputStream in = FirebaseScryptVectors.class.getResourceAsStream("/firebase-scrypt-vectors/" + file);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty() && !line.startsWith("#")) {
                    lines.add(line.split(",", -1));
                }
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return lines;
    }
}
