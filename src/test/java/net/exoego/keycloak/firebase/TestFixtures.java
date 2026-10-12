package net.exoego.keycloak.firebase;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.keycloak.Config;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.credential.PasswordCredentialModel;

import static net.exoego.keycloak.firebase.FirebaseScryptPasswordHashProviderFactory.MEM_COST;
import static net.exoego.keycloak.firebase.FirebaseScryptPasswordHashProviderFactory.ROUNDS;
import static net.exoego.keycloak.firebase.FirebaseScryptPasswordHashProviderFactory.SALT_SEPARATOR;
import static net.exoego.keycloak.firebase.FirebaseScryptPasswordHashProviderFactory.SIGNER_KEY;

final class TestFixtures {

    private TestFixtures() {
    }

    static Map<String, String> options() {
        Map<String, String> options = new HashMap<>();
        options.put(SIGNER_KEY, FirebaseScryptTest.KEY_01);
        options.put(SALT_SEPARATOR, FirebaseScryptTest.SALT_SEPARATOR);
        options.put(ROUNDS, String.valueOf(FirebaseScryptTest.ROUNDS));
        options.put(MEM_COST, String.valueOf(FirebaseScryptTest.MEM_COST));
        return options;
    }

    // A null value leaves the option out.
    static Map<String, String> options(String option, String value) {
        Map<String, String> options = options();
        if (value == null) {
            options.remove(option);
        } else {
            options.put(option, value);
        }
        return options;
    }

    static PasswordHashProvider provider(Map<String, String> options) {
        FirebaseScryptPasswordHashProviderFactory factory = new FirebaseScryptPasswordHashProviderFactory();
        factory.init(new MapScope(options));
        return factory.create(null);
    }

    // Same shape as the credentialData and secretData strings sent to the Admin API. A null leaves the field out.
    static PasswordCredentialModel imported(String hash, String salt) {
        StringBuilder secret = new StringBuilder("{");
        if (hash != null) {
            secret.append("\"value\":\"").append(hash).append("\",");
        }
        if (salt != null) {
            secret.append("\"salt\":\"").append(salt).append("\",");
        }
        secret.append("\"algorithmData\":{}}");

        CredentialModel model = new CredentialModel();
        model.setType(PasswordCredentialModel.TYPE);
        model.setCredentialData("{\"hashIterations\":8,\"algorithm\":\"firebase-scrypt\",\"algorithmData\":{}}");
        model.setSecretData(secret.toString());
        return PasswordCredentialModel.createFromCredentialModel(model);
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
