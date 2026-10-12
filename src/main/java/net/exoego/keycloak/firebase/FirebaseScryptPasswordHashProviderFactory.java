package net.exoego.keycloak.firebase;

import java.util.Base64;

import org.keycloak.Config;
import org.keycloak.common.Profile;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

import org.jboss.logging.Logger;

/**
 * Options, set per Firebase project:
 * <pre>
 * --spi-password-hashing--firebase-scrypt--signer-key=&lt;base64_signer_key&gt;
 * --spi-password-hashing--firebase-scrypt--salt-separator=&lt;base64_salt_separator&gt;
 * --spi-password-hashing--firebase-scrypt--rounds=&lt;rounds&gt;
 * --spi-password-hashing--firebase-scrypt--mem-cost=&lt;mem_cost&gt;
 * </pre>
 */
public class FirebaseScryptPasswordHashProviderFactory implements PasswordHashProviderFactory, EnvironmentDependentProviderFactory {

    public static final String ID = "firebase-scrypt";

    static final String SIGNER_KEY = "signer-key";
    static final String SALT_SEPARATOR = "salt-separator";
    static final String ROUNDS = "rounds";
    static final String MEM_COST = "mem-cost";

    private static final Logger logger = Logger.getLogger(FirebaseScryptPasswordHashProviderFactory.class);

    private byte[] signerKey;
    private byte[] saltSeparator;
    private int rounds;
    private int memCost;

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new FirebaseScryptPasswordHashProvider(signerKey, saltSeparator, rounds, memCost);
    }

    // Fail at startup. Without these values every migrated user would fail to log in.
    @Override
    public void init(Config.Scope config) {
        signerKey = requiredBase64(config, SIGNER_KEY);
        saltSeparator = requiredBase64(config, SALT_SEPARATOR);
        rounds = requiredInt(config, ROUNDS);
        memCost = requiredInt(config, MEM_COST);
        // Same limits as the Firebase Admin SDK. A larger mem-cost could make each login allocate gigabytes.
        if (rounds < 1 || rounds > 8) {
            throw new IllegalStateException(ID + ": rounds must be between 1 and 8");
        }
        if (memCost < 1 || memCost > 14) {
            throw new IllegalStateException(ID + ": mem-cost must be between 1 and 14");
        }
        logger.infof("%s enabled: rounds=%d, mem-cost=%d, signer key %d bytes", ID, rounds, memCost, signerKey.length);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }

    // Keycloak picks the highest positive order as the default algorithm. Keep this one out of that race.
    @Override
    public int order() {
        return -100;
    }

    // Same rule as the built-in argon2 provider. scrypt is not a FIPS approved algorithm.
    @Override
    public boolean isSupported(Config.Scope config) {
        return !Profile.isFeatureEnabled(Profile.Feature.FIPS);
    }

    private static byte[] requiredBase64(Config.Scope config, String key) {
        String value = config.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(ID + ": option " + key + " is required");
        }
        try {
            return Base64.getDecoder().decode(value.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException(ID + ": option " + key + " is not valid base64", e);
        }
    }

    private static int requiredInt(Config.Scope config, String key) {
        String value = config.get(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(ID + ": option " + key + " is required");
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException(ID + ": option " + key + " is not a number", e);
        }
    }
}
