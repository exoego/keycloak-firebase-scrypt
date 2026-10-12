package net.exoego.keycloak.firebase;

import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import com.sun.management.ThreadMXBean;
import org.bouncycastle.crypto.generators.SCrypt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test vectors from RFC 7914, sections 8 to 12. The scrypt vector with p = 16 and the one with N = 2^20 are left out.
 */
class ScryptTest {

    private static final HexFormat HEX = HexFormat.of();

    private static final String SALSA_IN = "7e879a214f3ec9867ca940e641718f26baee555b8c61c1b50df846116dcd3b1d"
            + "ee24f319df9b3d8514121e4b5ac5aa3276021d2909c74829edebc68db8b8c25e";
    private static final String SALSA_OUT = "a41f859c6608cc993b81cacb020cef05044b2181a2fd337dfd7b1c6396682f29"
            + "b4393168e3c9e6bcfe6bc5b7a06d96bae424cc102c91745c24ad673dc7618f81";

    private static final String BLOCK_MIX_IN = "f7ce0b653d2d72a4108cf5abe912ffdd777616dbbb27a70e8204f3ae2d0f6fad"
            + "89f68f4811d1e87bcc3bd7400a9ffd29094f0184639574f39ae5a1315217bcd7"
            + "894991447213bb226c25b54da86370fbcd984380374666bb8ffcb5bf40c254b0"
            + "67d27c51ce4ad5fed829c90b505a571b7f4d1cad6a523cda770e67bceaaf7e89";
    private static final String BLOCK_MIX_OUT = SALSA_OUT
            + "20edc975323881a80540f64c162dcd3c21077cfe5f8d5fe2b1a4168f953678b7"
            + "7d3b3d803b60e4ab920996e59b4d53b65d2a225877d5edf5842cb9f14eefe425";

    @Test
    void salsa20x8MatchesRfc7914() {
        int[] block = words(SALSA_IN);
        Scrypt.salsa20_8(block);
        assertArrayEquals(words(SALSA_OUT), block);
    }

    @Test
    void blockMixMatchesRfc7914() {
        int[] out = new int[32];
        Scrypt.blockMix(words(BLOCK_MIX_IN), 0, out, 0, 1, new int[16]);
        assertArrayEquals(words(BLOCK_MIX_OUT), out);
    }

    @Test
    void blockMixXorIsBlockMixOfTheXor() {
        Random random = new Random(7914);
        for (int r = 1; r <= 8; r++) {
            int[] in = random.ints(32 * r).toArray();
            int[] v = random.ints(32 * r * 3).toArray();
            int vOff = 32 * r;
            int[] xor = new int[32 * r];
            for (int k = 0; k < xor.length; k++) {
                xor[k] = in[k] ^ v[vOff + k];
            }
            int[] expected = new int[32 * r];
            Scrypt.blockMix(xor, 0, expected, 0, r, new int[16]);

            int[] actual = new int[32 * r];
            Scrypt.blockMixXor(in, v, vOff, actual, r, new int[16]);
            assertArrayEquals(expected, actual, "r=" + r);
        }
    }

    static Stream<Arguments> rfc7914Vectors() {
        return Stream.of(
                Arguments.of("", "", 4, 1, "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
                        + "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"),
                Arguments.of("pleaseletmein", "SodiumChloride", 14, 8, "7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2"
                        + "d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"));
    }

    @ParameterizedTest(name = "[{0}] N=2^{2} r={3}")
    @MethodSource("rfc7914Vectors")
    void matchesRfc7914(String password, String salt, int log2N, int r, String expected) {
        byte[] key = Scrypt.derive(password.getBytes(StandardCharsets.UTF_8), salt.getBytes(StandardCharsets.UTF_8), log2N, r, 64);
        assertEquals(expected, HEX.formatHex(key));
    }

    // Other parameters, the parameter range of the provider, and the empty password that needs the zero key.
    @ParameterizedTest(name = "[{0}] N=2^{1} r={2}")
    @CsvSource({
            "'', 1, 1",
            "'', 14, 8",
            "hunter2, 1, 1",
            "hunter2, 1, 8",
            "hunter2, 14, 1",
            "hunter2, 14, 8",
            "pässwörd, 10, 4",
            "hunter2, 3, 2",
            "hunter2, 5, 3",
            "hunter2, 7, 5",
            "hunter2, 9, 6",
            "hunter2, 11, 7",
    })
    void matchesBouncyCastle(String password, int log2N, int r) {
        byte[] p = password.getBytes(StandardCharsets.UTF_8);
        byte[] salt = new byte[11];
        new Random(log2N * 31 + r).nextBytes(salt);
        for (int dkLen : new int[] {32, 64}) {
            assertArrayEquals(SCrypt.generate(p, salt, 1 << log2N, r, 1, dkLen), Scrypt.derive(p, salt, log2N, r, dkLen));
        }
    }

    @Test
    void reusesTheWorkAreaBetweenCalls() {
        byte[] p = "hunter2".getBytes(StandardCharsets.UTF_8);
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        Scrypt.derive(p, salt, 14, 8, 32);

        ThreadMXBean threads = (ThreadMXBean) ManagementFactory.getThreadMXBean();
        long threadId = Thread.currentThread().getId();
        long before = threads.getThreadAllocatedBytes(threadId);
        Scrypt.derive(p, salt, 14, 8, 32);
        long allocated = threads.getThreadAllocatedBytes(threadId) - before;
        assertTrue(allocated < 1 << 20, "allocated " + allocated + " bytes, the work area alone is 16 MiB");
    }

    // Every thread has its own password, so a shared or zeroed buffer changes a result. Twice as many threads as
    // CPUs, so the pool runs dry and runs full, and several rounds, so a buffer passes from thread to thread.
    @Test
    void isThreadSafe() throws Exception {
        int threads = Runtime.getRuntime().availableProcessors() * 2;
        int rounds = 4;
        byte[] salt = "salt".getBytes(StandardCharsets.UTF_8);
        List<byte[]> passwords = IntStream.range(0, threads)
                .mapToObj(i -> ("password" + i).getBytes(StandardCharsets.UTF_8))
                .toList();
        List<byte[]> expected = passwords.stream().map(p -> Scrypt.derive(p, salt, 12, 8, 32)).toList();

        CyclicBarrier start = new CyclicBarrier(threads);
        List<Callable<byte[][]>> tasks = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            int first = t;
            tasks.add(() -> {
                start.await();
                byte[][] results = new byte[rounds][];
                for (int round = 0; round < rounds; round++) {
                    results[round] = Scrypt.derive(passwords.get((first + round) % threads), salt, 12, 8, 32);
                }
                return results;
            });
        }

        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<byte[][]>> futures = pool.invokeAll(tasks);
            for (int t = 0; t < threads; t++) {
                byte[][] results = futures.get(t).get();
                for (int round = 0; round < rounds; round++) {
                    assertArrayEquals(expected.get((t + round) % threads), results[round], "thread " + t + " round " + round);
                }
            }
        } finally {
            pool.shutdown();
        }
    }

    @Test
    void failsClearlyWithoutTheMac() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> Scrypt.hmac("HmacNONE", new byte[1]));
        assertEquals("HmacNONE is not available", e.getMessage());
        assertInstanceOf(NoSuchAlgorithmException.class, e.getCause());
    }

    private static int[] words(String hex) {
        byte[] bytes = HEX.parseHex(hex);
        int[] words = new int[bytes.length / 4];
        ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(words);
        return words;
    }
}
