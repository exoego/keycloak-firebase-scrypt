package net.exoego.keycloak.firebase;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.ModelException;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.credential.dto.PasswordSecretData;

/**
 * Verify-only provider for password hashes exported from Firebase Auth.
 * Keycloak rehashes the password with the realm default algorithm after the first successful login.
 */
public class FirebaseScryptPasswordHashProvider implements PasswordHashProvider {

    private final byte[] signerKey;
    private final byte[] saltSeparator;
    private final int rounds;
    private final int memCost;

    FirebaseScryptPasswordHashProvider(byte[] signerKey, byte[] saltSeparator, int rounds, int memCost) {
        this.signerKey = signerKey;
        this.saltSeparator = saltSeparator;
        this.rounds = rounds;
        this.memCost = memCost;
    }

    // Keycloak calls this only on the realm's target algorithm. Getting here means a misconfigured realm.
    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        return false;
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        throw verifyOnly();
    }

    @Override
    @Deprecated
    public String encode(String rawPassword, int iterations) {
        throw verifyOnly();
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        PasswordSecretData secret = credential.getPasswordSecretData();
        if (rawPassword == null || secret == null || secret.getSalt() == null || secret.getValue() == null) {
            return false;
        }
        // Strict decoder on purpose. A base64url value from the Firebase REST API must be converted before import.
        byte[] expected = Base64.getDecoder().decode(secret.getValue());
        byte[] actual = FirebaseScrypt.hash(rawPassword.getBytes(StandardCharsets.UTF_8), secret.getSalt(), saltSeparator,
                signerKey, rounds, memCost);
        return MessageDigest.isEqual(actual, expected);
    }

    @Override
    public String credentialHashingStrength(PasswordCredentialModel credential) {
        return String.format("FirebaseScrypt[N=2^%d,r=%d,p=1]", memCost, rounds);
    }

    @Override
    public void close() {
    }

    private static ModelException verifyOnly() {
        return new ModelException(FirebaseScryptPasswordHashProviderFactory.ID
                + " can only verify imported hashes. Use another algorithm (argon2) for new passwords.");
    }
}
