package dev.bug.encryption;

import dev.bug.encryption.exceptions.EncryptionException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;

public enum Transformation {

    RSA_ECB_PKCS1_PADDING("RSA/ECB/PKCS1Padding");

    private final String name;

    Transformation(String name) {
        this.name = name;
    }

    public Cipher getCipher() {
        try {
            return Cipher.getInstance(name);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            throw new EncryptionException(String.format("Failed to get a cipher: %s", name), ex);
        }
    }
}
