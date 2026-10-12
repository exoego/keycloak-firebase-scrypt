package net.exoego.keycloak.firebase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.ModelException;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.util.JsonSerialization;

import com.fasterxml.jackson.databind.JsonNode;

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

    // Keycloak logs an exception from here as a warning and denies the login, so a broken import is visible.
    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        // HMAC pads short keys with zero bytes, so "pw" and "pw\0" give the same hash.
        // Accepting "pw\0" would also rehash it as the new password and lock out the real one.
        if (rawPassword == null || rawPassword.indexOf('\0') >= 0) {
            return false;
        }
        byte[] salt = decodeSalt(credential.getSecretData());
        byte[] expected = decodeHash(credential.getPasswordSecretData().getValue());
        byte[] actual = FirebaseScrypt.hash(rawPassword.getBytes(StandardCharsets.UTF_8), salt, saltSeparator,
                signerKey, rounds, memCost);
        return MessageDigest.isEqual(actual, expected);
    }

    // Keycloak decodes the salt with the MIME decoder, which drops unknown characters such as "-" and "_".
    // So read the raw value and decode it strictly, as for the hash.
    private static byte[] decodeSalt(String secretData) {
        JsonNode salt;
        try {
            salt = JsonSerialization.mapper.readTree(secretData).get("salt");
        } catch (IOException e) {
            throw malformed("the secret data is not JSON");
        }
        return decodeBase64(salt == null ? null : salt.textValue(), "salt");
    }

    private byte[] decodeHash(String value) {
        byte[] hash = decodeBase64(value, "hash");
        // The Firebase hash is the signer key encrypted with AES-CTR, so both have the same length.
        if (hash.length != signerKey.length) {
            throw malformed("the hash has " + hash.length + " bytes, but the signer key has " + signerKey.length);
        }
        return hash;
    }

    private static byte[] decodeBase64(String value, String field) {
        if (value == null || value.isEmpty()) {
            throw malformed("the credential has no " + field);
        }
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw malformed("the " + field + " is not standard base64. Convert base64url values before import");
        }
    }

    @Override
    public String credentialHashingStrength(PasswordCredentialModel credential) {
        return String.format("FirebaseScrypt[N=2^%d,r=%d,p=1]", memCost, rounds);
    }

    @Override
    public void close() {
    }

    private static ModelException malformed(String reason) {
        return new ModelException(FirebaseScryptPasswordHashProviderFactory.ID + ": " + reason);
    }

    private static ModelException verifyOnly() {
        return new ModelException(FirebaseScryptPasswordHashProviderFactory.ID
                + " can only verify imported hashes. Use another algorithm (argon2) for new passwords.");
    }
}
