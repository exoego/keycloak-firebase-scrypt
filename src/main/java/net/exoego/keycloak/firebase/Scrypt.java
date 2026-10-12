package net.exoego.keycloak.firebase;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * scrypt as in RFC 7914, with p = 1, on the JDK alone.
 * <p>
 * The work area V takes 128 * r * N bytes, 16 MiB with the Firebase defaults. It is kept in a pool of at most one
 * per CPU and reused, so a login does not allocate it again. The pool holds only zeroed buffers.
 */
final class Scrypt {

    static final String HMAC_SHA256 = "HmacSHA256";

    private static final int SALSA_WORDS = 16;
    private static final ArrayBlockingQueue<int[]> POOL =
            new ArrayBlockingQueue<>(Runtime.getRuntime().availableProcessors());

    private Scrypt() {
    }

    /**
     * @param log2N log2 of the RFC's N. Firebase calls it mem_cost.
     * @param r the block size factor. Firebase calls it rounds.
     */
    static byte[] derive(byte[] password, byte[] salt, int log2N, int r, int dkLen) {
        int n = 1 << log2N;
        int blockWords = 32 * r;
        Mac mac = hmac(HMAC_SHA256, password);
        byte[] b = new byte[128 * r];
        int[] x = new int[blockWords];
        int[] y = new int[blockWords];
        int[] t = new int[SALSA_WORDS];
        int[] v = acquire(n * blockWords);
        try {
            pbkdf2(mac, salt, b);
            ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(x);

            // V[0] = B, V[i] = BlockMix(V[i - 1]), X = BlockMix(V[N - 1])
            System.arraycopy(x, 0, v, 0, blockWords);
            for (int i = 1; i < n; i++) {
                blockMix(v, (i - 1) * blockWords, v, i * blockWords, r, t);
            }
            blockMix(v, (n - 1) * blockWords, x, 0, r, t);

            // Integerify(X) mod N is the low bits of the first word of the last Salsa block.
            int mask = n - 1;
            for (int i = 0; i < n; i++) {
                int j = x[blockWords - SALSA_WORDS] & mask;
                blockMixXor(x, v, j * blockWords, y, r, t);
                int[] swap = x;
                x = y;
                y = swap;
            }

            ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().put(x);
            byte[] out = new byte[dkLen];
            pbkdf2(mac, b, out);
            return out;
        } finally {
            Arrays.fill(b, (byte) 0);
            Arrays.fill(x, 0);
            Arrays.fill(y, 0);
            Arrays.fill(t, 0);
            release(v);
        }
    }

    // A Keycloak has one set of parameters, so only the tests see buffers of another size.
    private static int[] acquire(int length) {
        int[] v;
        do {
            v = POOL.poll();
        } while (v != null && v.length != length);
        return v != null ? v : new int[length];
    }

    private static void release(int[] v) {
        Arrays.fill(v, 0);
        POOL.offer(v);
    }

    // out = BlockMix(in). t is scratch space of SALSA_WORDS.
    static void blockMix(int[] in, int inOff, int[] out, int outOff, int r, int[] t) {
        int blocks = 2 * r;
        System.arraycopy(in, inOff + (blocks - 1) * SALSA_WORDS, t, 0, SALSA_WORDS);
        for (int i = 0; i < blocks; i++) {
            int off = inOff + i * SALSA_WORDS;
            for (int k = 0; k < SALSA_WORDS; k++) {
                t[k] ^= in[off + k];
            }
            salsa20_8(t);
            System.arraycopy(t, 0, out, outOff + outputBlock(i, r) * SALSA_WORDS, SALSA_WORDS);
        }
    }

    // out = BlockMix(in XOR v[vOff..]). The XOR is done on the fly, so the sum is never written anywhere.
    static void blockMixXor(int[] in, int[] v, int vOff, int[] out, int r, int[] t) {
        int blocks = 2 * r;
        int last = (blocks - 1) * SALSA_WORDS;
        for (int k = 0; k < SALSA_WORDS; k++) {
            t[k] = in[last + k] ^ v[vOff + last + k];
        }
        for (int i = 0; i < blocks; i++) {
            int off = i * SALSA_WORDS;
            for (int k = 0; k < SALSA_WORDS; k++) {
                t[k] ^= in[off + k] ^ v[vOff + off + k];
            }
            salsa20_8(t);
            System.arraycopy(t, 0, out, outputBlock(i, r) * SALSA_WORDS, SALSA_WORDS);
        }
    }

    // BlockMix writes the even outputs to the first half and the odd outputs to the second half.
    private static int outputBlock(int i, int r) {
        return (i & 1) == 0 ? i >> 1 : r + (i >> 1);
    }

    static void salsa20_8(int[] b) {
        int x0 = b[0], x1 = b[1], x2 = b[2], x3 = b[3], x4 = b[4], x5 = b[5], x6 = b[6], x7 = b[7],
                x8 = b[8], x9 = b[9], x10 = b[10], x11 = b[11], x12 = b[12], x13 = b[13], x14 = b[14], x15 = b[15];
        for (int i = 0; i < 4; i++) {
            x4 ^= Integer.rotateLeft(x0 + x12, 7);
            x8 ^= Integer.rotateLeft(x4 + x0, 9);
            x12 ^= Integer.rotateLeft(x8 + x4, 13);
            x0 ^= Integer.rotateLeft(x12 + x8, 18);
            x9 ^= Integer.rotateLeft(x5 + x1, 7);
            x13 ^= Integer.rotateLeft(x9 + x5, 9);
            x1 ^= Integer.rotateLeft(x13 + x9, 13);
            x5 ^= Integer.rotateLeft(x1 + x13, 18);
            x14 ^= Integer.rotateLeft(x10 + x6, 7);
            x2 ^= Integer.rotateLeft(x14 + x10, 9);
            x6 ^= Integer.rotateLeft(x2 + x14, 13);
            x10 ^= Integer.rotateLeft(x6 + x2, 18);
            x3 ^= Integer.rotateLeft(x15 + x11, 7);
            x7 ^= Integer.rotateLeft(x3 + x15, 9);
            x11 ^= Integer.rotateLeft(x7 + x3, 13);
            x15 ^= Integer.rotateLeft(x11 + x7, 18);
            x1 ^= Integer.rotateLeft(x0 + x3, 7);
            x2 ^= Integer.rotateLeft(x1 + x0, 9);
            x3 ^= Integer.rotateLeft(x2 + x1, 13);
            x0 ^= Integer.rotateLeft(x3 + x2, 18);
            x6 ^= Integer.rotateLeft(x5 + x4, 7);
            x7 ^= Integer.rotateLeft(x6 + x5, 9);
            x4 ^= Integer.rotateLeft(x7 + x6, 13);
            x5 ^= Integer.rotateLeft(x4 + x7, 18);
            x11 ^= Integer.rotateLeft(x10 + x9, 7);
            x8 ^= Integer.rotateLeft(x11 + x10, 9);
            x9 ^= Integer.rotateLeft(x8 + x11, 13);
            x10 ^= Integer.rotateLeft(x9 + x8, 18);
            x12 ^= Integer.rotateLeft(x15 + x14, 7);
            x13 ^= Integer.rotateLeft(x12 + x15, 9);
            x14 ^= Integer.rotateLeft(x13 + x12, 13);
            x15 ^= Integer.rotateLeft(x14 + x13, 18);
        }
        b[0] += x0;
        b[1] += x1;
        b[2] += x2;
        b[3] += x3;
        b[4] += x4;
        b[5] += x5;
        b[6] += x6;
        b[7] += x7;
        b[8] += x8;
        b[9] += x9;
        b[10] += x10;
        b[11] += x11;
        b[12] += x12;
        b[13] += x13;
        b[14] += x14;
        b[15] += x15;
    }

    // PBKDF2 with one iteration: block i of the output is HMAC(salt || i).
    private static void pbkdf2(Mac mac, byte[] salt, byte[] out) {
        for (int block = 1, off = 0; off < out.length; block++, off += 32) {
            mac.update(salt);
            mac.update((byte) (block >>> 24));
            mac.update((byte) (block >>> 16));
            mac.update((byte) (block >>> 8));
            mac.update((byte) block);
            byte[] hash = mac.doFinal();
            System.arraycopy(hash, 0, out, off, Math.min(hash.length, out.length - off));
        }
    }

    // SecretKeySpec rejects an empty key. HMAC pads a shorter key with zero bytes up to the block size of
    // the hash, so 64 zero bytes give the same result as no bytes.
    static Mac hmac(String algorithm, byte[] key) {
        try {
            Mac mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[64] : key, algorithm));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(algorithm + " is not available", e);
        }
    }
}
