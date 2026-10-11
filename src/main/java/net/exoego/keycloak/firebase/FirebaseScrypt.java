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
            Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
            aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derived, 0, AES_KEY_LENGTH, "AES"), new IvParameterSpec(new byte[16]));
            return aes.doFinal(signerKey);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-CTR is not available", e);
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }
}
