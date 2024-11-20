package org.task.Cripto.service;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.security.*;

@Service
public class EncryptionService {

    public String caesarEncrypt(String message, int shift) {
        StringBuilder encrypted = new StringBuilder();
        for (char c : message.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isLowerCase(c) ? 'a' : 'A';
                encrypted.append((char) ((c - base + shift) % 26 + base));
            } else {
                encrypted.append(c);
            }
        }
        return encrypted.toString();
    }

    public String caesarDecrypt(String encrypted, int shift) {
        return caesarEncrypt(encrypted, 26 - shift);
    }
//<======================================================================>
    private final SecretKey aesKey;
    private final KeyPair rsaKeysOFF;
    public EncryptionService() throws Exception {
        KeyGenerator keyGenAES = KeyGenerator.getInstance("AES");
        keyGenAES.init(128);
        this.aesKey = keyGenAES.generateKey();

        KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance("RSA");
        keyGenRSA.initialize(2048);
        this.rsaKeysOFF = keyGenRSA.generateKeyPair();
    }
    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(rsaKeysOFF.getPublic().getEncoded());
    }
    public String getPrivateKey() {
        return Base64.getEncoder().encodeToString(rsaKeysOFF.getPrivate().getEncoded());
    }

    //<======================================================================>
    public String aesEncrypt(String message, String key) throws Exception {
//        byte[] decodedKey = Base64.getDecoder().decode(key);
//        SecretKey aesKey0 = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
    public String getAesKeyOFF() {
        return Base64.getEncoder().encodeToString(aesKey.getEncoded());
    }
public String getAesKey(String key) throws Exception {
//    String key = messageService.sendGengerateKey("rsa");

    byte[] keyBytes = Base64.getDecoder().decode(key);
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey = keyFactory.generatePublic(spec);

    byte[] aesKeyBytes = aesKey.getEncoded();

    Cipher cipher = Cipher.getInstance("RSA");
    cipher.init(Cipher.ENCRYPT_MODE, publicKey);
    byte[] encrypted = cipher.doFinal(aesKeyBytes);

    return Base64.getEncoder().encodeToString(encrypted);
}

//<======================================================================>

    public String rsaEncrypt(String message, String key) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(spec);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }


}
