package dev.bug.encryption;

import dev.bug.encryption.exceptions.EncryptionException;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public enum Algorithm {

    RSA("RSA");

    private final String name;

    Algorithm(String name) {
        this.name = name;
    }

    public KeyPairGenerator getKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance(name);
        } catch (NoSuchAlgorithmException ex) {
            throw new EncryptionException(String.format("Failed to get a KeyPairGenerator: %s", name), ex);
        }
    }
}
