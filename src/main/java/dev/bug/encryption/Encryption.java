package dev.bug.encryption;

import dev.bug.encryption.exceptions.ExportKeyException;

import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import java.util.Objects;

public class Encryption {

    private static final int KEY_SIZE = 2048;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final Cipher cipher;

    public Encryption(Algorithm algorithm, Transformation transformation) {
        KeyPairGenerator generator = algorithm.getKeyPairGenerator();
        generator.initialize(KEY_SIZE);
        KeyPair pair = generator.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
        cipher = transformation.getCipher();
    }

    public String encrypt(String message) throws GeneralSecurityException {
        byte[] messageToBytes = message.getBytes();
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(messageToBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws GeneralSecurityException {
        byte[] encryptedBytes = decode(encryptedMessage);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedBytes);
        return new String(decryptedMessage, StandardCharsets.UTF_8);
    }

    public String getPublicKey() {
        return encode(publicKey.getEncoded());
    }

    public String getPrivateKey() {
        return encode(privateKey.getEncoded());
    }

    public void printKeys() {
        System.err.println("Public key:\n" + getPublicKey());
        System.err.println("Private key:\n" + getPrivateKey());
    }

    public void exportPublicKey(String path) {
        String key = encode(publicKey.getEncoded());
        writeToFile(Paths.get(path), key);
    }

    public void exportPrivateKey(String path) {
        String key = encode(privateKey.getEncoded());
        writeToFile(Paths.get(path), key);
    }

    private void writeToFile(Path path, String key) {
        try {
            Path directory = path.getParent();
            if (Objects.nonNull(directory)) {
                Files.createDirectories(directory);
            }
            Files.write(path, key.getBytes(StandardCharsets.UTF_8));
        } catch (IOException ex) {
            throw new ExportKeyException(String.format("Unsuccessful key exportation: %s", path.toFile()), ex);
        }
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}
