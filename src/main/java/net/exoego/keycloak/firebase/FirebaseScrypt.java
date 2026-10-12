package net.exoego.keycloak.firebase;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.generators.SCrypt;

/**
 * Firebase Auth's modified scrypt, ported from scryptenc_buf_saltlen() in
 * https://github.com/firebase/scrypt (lib/scryptenc/scryptenc.c).
 */
final class FirebaseScrypt {

    private static final int DERIVED_KEY_LENGTH = 64;
    private static final int AES_KEY_LENGTH = 32;
    private static final int PARALLELISM = 1;
    private static final String AES_CTR = "AES/CTR/NoPadding";

    private FirebaseScrypt() {
    }

    static byte[] hash(byte[] password, byte[] userSalt, byte[] saltSeparator, byte[] signerKey, int rounds, int memCost) {
        byte[] salt = new byte[userSalt.length + saltSeparator.length];
        System.arraycopy(userSalt, 0, salt, 0, userSalt.length);
        System.arraycopy(saltSeparator, 0, salt, userSalt.length, saltSeparator.length);

        byte[] derived = SCrypt.generate(password, salt, 1 << memCost, rounds, PARALLELISM, DERIVED_KEY_LENGTH);
        try {
            // Firebase does not store the scrypt output. It stores the signer key encrypted with
            // AES-256-CTR, keyed by the first 32 bytes of the output. The counter block starts at zero.
            return encrypt(AES_CTR, derived, signerKey);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }

    // Java platforms do not have to support AES/CTR, so a JVM may lack it.
    static byte[] encrypt(String transformation, byte[] key, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 0, AES_KEY_LENGTH, "AES"), new IvParameterSpec(new byte[16]));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(transformation + " is not available", e);
        }
    }
}
