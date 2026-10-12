package net.exoego.keycloak.firebase;

import java.util.Arrays;

import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

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
            StreamCipher aes = SICBlockCipher.newInstance(AESEngine.newInstance());
            aes.init(true, new ParametersWithIV(new KeyParameter(derived, 0, AES_KEY_LENGTH), new byte[16]));
            byte[] hash = new byte[signerKey.length];
            aes.processBytes(signerKey, 0, signerKey.length, hash, 0);
            return hash;
        } finally {
            Arrays.fill(derived, (byte) 0);
        }
    }
}
