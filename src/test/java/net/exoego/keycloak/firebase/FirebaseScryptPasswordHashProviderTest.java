package net.exoego.keycloak.firebase;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.keycloak.Config;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.ModelException;
import org.keycloak.models.credential.PasswordCredentialModel;

import org.junit.jupiter.api.Test;

import static net.exoego.keycloak.firebase.FirebaseScryptTest.HUNTER2_HASH;
import static net.exoego.keycloak.firebase.FirebaseScryptTest.HUNTER2_SALT;
import static net.exoego.keycloak.firebase.FirebaseScryptTest.KEY_01;
import static net.exoego.keycloak.firebase.FirebaseScryptTest.KEY_02;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FirebaseScryptPasswordHashProviderTest {

    // Same shape as the credentialData and secretData strings sent to the Admin API.
    static PasswordCredentialModel imported(String hash, String salt) {
        CredentialModel model = new CredentialModel();
        model.setType(PasswordCredentialModel.TYPE);
        model.setCredentialData("{\"hashIterations\":8,\"algorithm\":\"firebase-scrypt\",\"algorithmData\":{}}");
        model.setSecretData("{\"value\":\"" + hash + "\",\"salt\":\"" + salt + "\",\"algorithmData\":{}}");
        return PasswordCredentialModel.createFromCredentialModel(model);
    }

    static Map<String, String> options(String signerKey) {
        Map<String, String> options = new HashMap<>();
        options.put(FirebaseScryptPasswordHashProviderFactory.SIGNER_KEY, signerKey);
        options.put(FirebaseScryptPasswordHashProviderFactory.SALT_SEPARATOR, FirebaseScryptTest.SALT_SEPARATOR);
        options.put(FirebaseScryptPasswordHashProviderFactory.ROUNDS, "8");
        options.put(FirebaseScryptPasswordHashProviderFactory.MEM_COST, "14");
        return options;
    }

    static PasswordHashProvider provider(Map<String, String> options) {
        FirebaseScryptPasswordHashProviderFactory factory = new FirebaseScryptPasswordHashProviderFactory();
        factory.init(new MapScope(options));
        return factory.create(null);
    }

    private final PasswordHashProvider provider = provider(options(KEY_01));
    private final PasswordCredentialModel hunter2 = imported(HUNTER2_HASH, HUNTER2_SALT);

    @Test
    void importedCredentialParses() {
        assertEquals("firebase-scrypt", hunter2.getPasswordCredentialData().getAlgorithm());
        assertEquals(10, hunter2.getPasswordSecretData().getSalt().length);
    }

    @Test
    void acceptsCorrectPassword() {
        assertTrue(provider.verify("hunter2", hunter2));
    }

    @Test
    void rejectsWrongPassword() {
        assertFalse(provider.verify("hunter3", hunter2));
        assertFalse(provider.verify("Hunter2", hunter2));
        assertFalse(provider.verify("hunter2 ", hunter2));
        assertFalse(provider.verify("", hunter2));
        assertFalse(provider.verify(null, hunter2));
    }

    @Test
    void rejectsWhenSignerKeyIsFromAnotherProject() {
        assertFalse(provider(options(KEY_02)).verify("hunter2", hunter2));
    }

    @Test
    void rejectsBase64UrlHash() {
        String urlSafe = HUNTER2_HASH.replace('+', '-').replace('/', '_');
        assertThrows(IllegalArgumentException.class, () -> provider.verify("hunter2", imported(urlSafe, HUNTER2_SALT)));
    }

    @Test
    void refusesToCreateHashes() {
        assertThrows(ModelException.class, () -> provider.encodedCredential("hunter2", -1));
        assertThrows(ModelException.class, () -> provider.encode("hunter2", -1));
    }

    @Test
    void neverReportsCredentialAsUpToDate() {
        assertFalse(provider.policyCheck(null, hunter2));
    }

    @Test
    void initFailsOnMissingOrInvalidOptions() {
        Map<String, String> missingKey = options(KEY_01);
        missingKey.remove(FirebaseScryptPasswordHashProviderFactory.SIGNER_KEY);
        assertThrows(IllegalStateException.class, () -> provider(missingKey));

        Map<String, String> badBase64 = options("not base64!");
        assertThrows(IllegalStateException.class, () -> provider(badBase64));

        Map<String, String> badMemCost = options(KEY_01);
        badMemCost.put(FirebaseScryptPasswordHashProviderFactory.MEM_COST, "0");
        assertThrows(IllegalStateException.class, () -> provider(badMemCost));
    }

    static class MapScope extends Config.AbstractScope {
        private final Map<String, String> values;

        MapScope(Map<String, String> values) {
            this.values = values;
        }

        @Override
        public String get(String key) {
            return values.get(key);
        }

        @Override
        public Config.Scope scope(String... scope) {
            throw new UnsupportedOperationException();
        }

        @Override
        @Deprecated
        public Set<String> getPropertyNames() {
            return values.keySet();
        }

        @Override
        public Config.Scope root() {
            return this;
        }
    }
}
