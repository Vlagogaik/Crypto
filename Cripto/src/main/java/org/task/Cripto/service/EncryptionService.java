package org.task.Cripto.service;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
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
    public EncryptionService() throws Exception {
    }
//<======================================================================>
    public String aesEncrypt(String message, String key) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKey aesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }
//<======================================================================>
    public RSAPublicKey generateRSAPublicKey(BigInteger n, BigInteger e) throws Exception {
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    }

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
    //<==============================RC4=====================================>
    public byte[] generateKeyStream(byte[] key) {
        byte[] state = new byte[256];
        byte[] keySchedule = new byte[256];

        for (int i = 0; i < 256; i++) {
            state[i] = (byte) i;
            keySchedule[i] = key[i % key.length];
        }

        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + state[i] + keySchedule[i]) & 0xFF;
            byte temp = state[i];
            state[i] = state[j];
            state[j] = temp;
        }

        byte[] keyStream = new byte[256];
        int i = 0, k = 0;
        for (int n = 0; n < 256; n++) {
            i = (i + 1) & 0xFF;
            k = (k + state[i]) & 0xFF;
            byte temp = state[i];
            state[i] = state[k];
            state[k] = temp;
            keyStream[n] = state[(state[i] + state[k]) & 0xFF];
        }

        return keyStream;
    }
    public String encryptRC4(String data, String base64Key) {
        byte[] key = Base64.getDecoder().decode(base64Key);
        byte[] dataBytes = data.getBytes();
        byte[] keyStream = generateKeyStream(key);

        byte[] encryptedData = new byte[dataBytes.length];
        int i = 0, j = 0;
        for (int n = 0; n < dataBytes.length; n++) {
            i = (i + 1) & 0xFF;
            j = (j + keyStream[i]) & 0xFF;

            byte temp = keyStream[i];
            keyStream[i] = keyStream[j];
            keyStream[j] = temp;

            encryptedData[n] = (byte) (dataBytes[n] ^ keyStream[(keyStream[i] + keyStream[j]) & 0xFF]);
        }

        return Base64.getEncoder().encodeToString(encryptedData);
    }
    public String decryptRC4(String encryptedData, String base64Key) {
        byte[] key = Base64.getDecoder().decode(base64Key);
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);
        byte[] keyStream = generateKeyStream(key);

        byte[] decryptedData = new byte[encryptedBytes.length];
        int i = 0, j = 0;
        for (int n = 0; n < encryptedBytes.length; n++) {
            i = (i + 1) & 0xFF;
            j = (j + keyStream[i]) & 0xFF;

            byte temp = keyStream[i];
            keyStream[i] = keyStream[j];
            keyStream[j] = temp;

            decryptedData[n] = (byte) (encryptedBytes[n] ^ keyStream[(keyStream[i] + keyStream[j]) & 0xFF]);
        }

        return new String(decryptedData);
    }
    public String generateRC4Key() {
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) {
            key[i] = (byte) (Math.random() * 256);
        }

        return Base64.getEncoder().encodeToString(key);
    }
//<=============================/RC4=====================================>

}
