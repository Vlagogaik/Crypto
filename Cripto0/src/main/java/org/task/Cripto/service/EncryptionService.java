package org.task.Cripto.service;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.security.*;
import java.util.Random;
import java.math.BigInteger;
import java.security.SecureRandom;

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
    public String getCaesatKey(){
        Random random = new Random();
        int randomNumber = random.nextInt(26) + 1;
        return String.valueOf(randomNumber);
    }
//<======================================================================>
    private final KeyPair rsaKeys;
    PublicKey publicKey ;
    PrivateKey privateKey ;
    private SecretKey aesKeyoff;

//<==========================AES=========================================>
    public void generateAESKey() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[16];
        secureRandom.nextBytes(keyBytes);
        this.aesKeyoff = new SecretKeySpec(keyBytes, "AES");
    }

//<==========================RSA=========================================>
    public String convertToX509Format(BigInteger n, BigInteger e) throws Exception {
        RSAPublicKey rsaPublicKey = generateRSAPublicKey(n, e);
        byte[] encodedKey = rsaPublicKey.getEncoded();
        return Base64.getEncoder().encodeToString(encodedKey);
    }
    public RSAPublicKey generateRSAPublicKey(BigInteger n, BigInteger e) throws Exception {
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(n, e);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
    }

    public RSAPrivateKey generateRSAPrivateKey(BigInteger n, BigInteger e, BigInteger d) throws Exception {
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(n, d);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }


    public byte[] getEncoded(BigInteger n, BigInteger e) {
        // X.509 с использованием ASN.1
        byte[] nBytes = n.toByteArray();
        byte[] eBytes = e.toByteArray();

        byte[] encodedKey = new byte[2 + nBytes.length + eBytes.length];
        encodedKey[0] = (byte) 0x30;
        encodedKey[1] = (byte) (2 + nBytes.length + eBytes.length);

        System.arraycopy(nBytes, 0, encodedKey, 2, nBytes.length);
        System.arraycopy(eBytes, 0, encodedKey, 2 + nBytes.length, eBytes.length);

        return encodedKey;
    }
    private byte[] getEncodedPrivateKey(BigInteger n, BigInteger e, BigInteger d) {
        byte[] nBytes = n.toByteArray();
        byte[] eBytes = e.toByteArray();
        byte[] dBytes = d.toByteArray();

        // PKCS#8
        byte[] encodedKey = new byte[2 + nBytes.length + eBytes.length + dBytes.length];
        encodedKey[0] = (byte) 0x30;
        encodedKey[1] = (byte) (2 + nBytes.length + eBytes.length + dBytes.length);

        System.arraycopy(nBytes, 0, encodedKey, 2, nBytes.length);
        System.arraycopy(eBytes, 0, encodedKey, 2 + nBytes.length, eBytes.length);
        System.arraycopy(dBytes, 0, encodedKey, 2 + nBytes.length + eBytes.length, dBytes.length);

        return encodedKey;
    }
    public KeyPair generateKeyPair(BigInteger n, BigInteger e, BigInteger d) throws Exception {
        RSAPublicKey publicKey = generateRSAPublicKey(n, e);
        RSAPrivateKey privateKey = generateRSAPrivateKey(n, e, d);
        return new KeyPair(publicKey, privateKey);
    }
//<=========================/RSA=========================================>
    public EncryptionService() throws Exception {
        try {
            generateAESKey();
            //<==========================RSA=========================================>
            SecureRandom random = new SecureRandom();
            int bitLength = 2048;
            BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
            BigInteger q = BigInteger.probablePrime(bitLength / 2, random);

            BigInteger n = p.multiply(q);
            BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

            BigInteger e = BigInteger.probablePrime(bitLength / 2, random);
            while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
                e.add(BigInteger.ONE);
            }
            BigInteger d = e.modInverse(phi);

            this.rsaKeys = generateKeyPair(n, e, d);

        } catch (Exception ex) {
            ex.printStackTrace();
            throw new Exception("Error initializing EncryptionService", ex);
        }

//<=========================/RSA=========================================>
    }
    public String getAesKeyOFF() {
        return Base64.getEncoder().encodeToString(aesKeyoff.getEncoded());
    }
//<======================================================================>
    public String aesDecrypt(String encryptedMessage, String encryptedKey) throws Exception {
        byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
        SecretKey aesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES");

        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decryptedMessageBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedMessage));

        return new String(decryptedMessageBytes);
    }

//<======================================================================>
    public String rsaDecrypt(String encryptedMessage) throws Exception {

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate());
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decrypted);
    }

    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(rsaKeys.getPublic().getEncoded());
    }
    public String getPrivateKey() {
        return Base64.getEncoder().encodeToString(rsaKeys.getPrivate().getEncoded());
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
