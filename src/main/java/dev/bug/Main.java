package dev.bug;

import dev.bug.encryption.Encryption;

import java.security.GeneralSecurityException;

import static dev.bug.encryption.Algorithm.RSA;
import static dev.bug.encryption.Transformation.RSA_ECB_PKCS1_PADDING;

public class Main {
    public static void main(String[] args) {
        Encryption encryption = new Encryption(RSA, RSA_ECB_PKCS1_PADDING);
        try {
            String encryptMessage = encryption.encrypt("Привет!");
            String decryptMessage = encryption.decrypt(encryptMessage);
            System.out.println("Encryption:\n" + encryptMessage);
            System.out.println("Description:\n" + decryptMessage);
            encryption.printKeys();

            encryption.exportPublicKey("RSA/public_key.pem");
            encryption.exportPrivateKey("RSA/private_key.pem");
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
        }
    }
}
