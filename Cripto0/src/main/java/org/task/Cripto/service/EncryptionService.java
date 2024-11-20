package org.task.Cripto.service;
import org.springframework.stereotype.Service;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
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
    public String caesarDecryptOff(String encrypted) {
        return caesarEncrypt(encrypted, 26 - 23);
    }
//<======================================================================>
    private final KeyPair rsaKeys;
    private final SecretKey aesKeyoff;
    public EncryptionService() throws Exception {
        KeyGenerator keyGenAES = KeyGenerator.getInstance("AES");
        keyGenAES.init(128);
        this.aesKeyoff = keyGenAES.generateKey();

        KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance("RSA");
        keyGenRSA.initialize(2048);
        this.rsaKeys = keyGenRSA.generateKeyPair();
    }
    public String getAesKeyOFF() {
        return Base64.getEncoder().encodeToString(aesKeyoff.getEncoded());
    }
//<======================================================================>
    public String aesDecrypt(String encryptedMessage, String encryptedKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, rsaKeys.getPrivate());
        byte[] decryptedKeyBytes = rsaCipher.doFinal(Base64.getDecoder().decode(encryptedKey));

        SecretKey aesKey = new SecretKeySpec(decryptedKeyBytes, "AES");

        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decryptedMessageBytes = aesCipher.doFinal(Base64.getDecoder().decode(encryptedMessage));

        return new String(decryptedMessageBytes);
    }
    public String aesDecryptOff(String encryptedMessage) throws Exception {
        String aesKey = "mysecretkey12345";
        SecretKey secretKey = new SecretKeySpec(aesKey.getBytes(), "AES");
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
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
    public String rsaDecryptOff(String message) throws Exception {
        String publicKey ="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2OBZbrrKof0V1SR73CViC4QEwtIxMm8OGXF/jJWMkIexgwCKYfsgp8PloPVHoarzkEQgNpXk5315bhdw+Vd1qDm9NkB9u8HcKqV7hKiVqvzbR20+dyyG3GOcELRVKvGCvnj8GgJ7J2aGT6+ZEkI1J8XQ6mzuU/LeUFQrRfQ1CI2/uiu895uzsBbMG81AKZsGGZNpiLkfmzHqSoHiIjojkbG6qHpobp9YGZzt/pN3mBvmGeMiqQFBDIQHz7zlxVYEw9iI7J6pYJCSugigTepX3ZZE72c3QpYDJueK+WQT12P9mNt8HXB0+IXxmWtOUZID768ImfHenCSIelUWDKDxLwIDAQAB";
        String privateKey="MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDY4Fluusqh/RXVJHvcJWILhATC0jEybw4ZcX+MlYyQh7GDAIph+yCnw+Wg9UehqvOQRCA2leTnfXluF3D5V3WoOb02QH27wdwqpXuEqJWq/NtHbT53LIbcY5wQtFUq8YK+ePwaAnsnZoZPr5kSQjUnxdDqbO5T8t5QVCtF9DUIjb+6K7z3m7OwFswbzUApmwYZk2mIuR+bMepKgeIiOiORsbqoemhun1gZnO3+k3eYG+YZ4yKpAUEMhAfPvOXFVgTD2IjsnqlgkJK6CKBN6lfdlkTvZzdClgMm54r5ZBPXY/2Y23wdcHT4hfGZa05RkgPvrwiZ8d6cJIh6VRYMoPEvAgMBAAECggEAB+4UIby0whLl+c2ECzsBXcMYWs34EeGxAJ8qIcgqGUgiO9ReOvzwEbz+UtIFKip9DhkKRdSvR65KgrWwDNNKMGTZaqLAYN19dmsR8Xop7CmjaaDbTYeURXoNmn1ti8zEPMC3FHW4w7+3njGhMDi5hthwg3yI2Qr4CV86gdakcHPlLnZkuTdk1AQHlMk9B2HJc5Z7BQB362XEr8Q59SVk7TPQF7AzRYsfJLHO1D+2Fx2RZGssHtqU6gW6tUGtdYIXdeBgKD+ztkkM0XpM1GEjL/ucp8Mt6+kiSKLHEUmNZIMgItnMvW4u3E1NAjiDFf8COzsHatxFscmM8dA+HNI5aQKBgQDs+f1ToXUBOezaYX7S+XAovOTZsZSwMqAzOvM6ndweZnf4sHef+RYZB0FKXri3xheiJvtWCsZqRC7Posw7BUpdTCuHTuvuUhHwxRy3PTfk2HkK8R3wOWAjU2bVxKKeEB4V99/yM/qpNoteBqF4RcHMbWbPK+Tp8JTYk08SH/GkOwKBgQDqSUoYnWTnJ/rEvIiPzlS5ZD0LLWii/GtjyH0zCF8Uqqp3ogRjyBLXUuyNJgK9GM9mz/ulzOkjkHadYWxxJibT8p5wMH9ZhbTkIoZ13Zms6K7o8M7HAjB5+H61sps2q7DzRpyA/CDDjR3MEPhYd3zdfzo7Sx1iRXD7/2V1OocbnQKBgDFv1ZFk1Wv0EZ1dSX/p2aQmA/gGO+amKRWG7scDt6//4HdZGRuecyW1hcFmEVMFWFjTmQtSJCJ3JuzaIZEOgX0FLu+DX2TQaj24YU040DhFkLrfokdDMPMtqv5djy86XYxnsahtf5Vdc6Wh7H2Sz+M9z3zYw2Cqd+LWmGBHmbmRAoGBAIM5B4Jf7ds23lMBEjARrgykozg2d8wKO5AJBG7n+nFV4eLd4T2OG1d1P78TEied1NTOGzHTYqWjzXv6zEVXzBmcY7eMwld+90FsQQmVU/Sv4v/fmMGIbWRzlWzpm9v0MEkiPJhWH3fH+2+H9cF/M3XQQ+pf+RZItK7AbrBJVtFVAoGATTShpcWW4SJnhxP+tZC4d79NNUW3K3SyXvVqECdHVUTCAPHxjEgnqSiPR7Yp8KZBZFTB3wUwIJOV6nDzYyEyIGwqQf6KlP/HqUz5nZyGITpf+t/WbbE2z+dPxekqc3DTGLDMj55SX67yqfSk3AbpId/Y2rNoZVPE8kLCFDqDY1Y=";
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey1 = keyFactory.generatePrivate(spec);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey1);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(message));
        return new String(decrypted);
    }

    public String getPublicKey() {
        return Base64.getEncoder().encodeToString(rsaKeys.getPublic().getEncoded());
    }
    public String getPrivateKey() {
        return Base64.getEncoder().encodeToString(rsaKeys.getPrivate().getEncoded());
    }
}
