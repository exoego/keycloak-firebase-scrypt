package net.exoego.keycloak.firebase;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Firebase Auth's modified scrypt, ported from scryptenc_buf_saltlen() in
 * https://github.com/firebase/scrypt (lib/scryptenc/scryptenc.c).
 */
final class FirebaseScrypt {

    private static final int AES_KEY_LENGTH = 32;
    private static final String AES_CTR = "AES/CTR/NoPadding";

    private FirebaseScrypt() {
    }

    static byte[] hash(byte[] password, byte[] userSalt, byte[] saltSeparator, byte[] signerKey, int rounds, int memCost) {
        byte[] salt = new byte[userSalt.length + saltSeparator.length];
        System.arraycopy(userSalt, 0, salt, 0, userSalt.length);
        System.arraycopy(saltSeparator, 0, salt, userSalt.length, saltSeparator.length);

        // Firebase derives 64 bytes and uses only the first 32. The first 32 bytes are the same for any length.
        byte[] key = Scrypt.derive(password, salt, memCost, rounds, AES_KEY_LENGTH);
        try {
            // Firebase does not store the scrypt output. It stores the signer key encrypted with
            // AES-256-CTR, keyed by the scrypt output. The counter block starts at zero.
            return encrypt(AES_CTR, key, signerKey);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    // Java platforms do not have to support AES/CTR, so a JVM may lack it.
    static byte[] encrypt(String transformation, byte[] key, byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(transformation + " is not available", e);
        }
    }
}
