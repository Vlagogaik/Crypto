package org.task.Cripto.controller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.task.Cripto.service.EncryptionService;
import org.task.Cripto.service.MessageService;

import java.util.Base64;
import java.util.Map;
import java.util.Random;
import lombok.extern.slf4j.Slf4j;

//@Slf4j
@RestController
@RequestMapping("/api")
public class EncryptionController {
    private static final Logger log = LoggerFactory.getLogger(EncryptionController.class);
    private final EncryptionService encryptionService;
    private final MessageService messageService;
    private String privateKey;

    public EncryptionController(EncryptionService encryptionService, MessageService messageService) {
        this.encryptionService = encryptionService;
        this.messageService = messageService;
    }

    @PostMapping("/get_encrypted_msg ")
    public String SendCryptoMessage(@RequestBody Map<String, String> request) throws Exception {
        String encryptedMessage = request.get("message");
        String method = request.get("method");
        log.info("Decrypting message: '{}' with method: '{}'", encryptedMessage, method);

        switch (method.toLowerCase()) {
            case "caesar":
                return encryptionService.caesarDecryptOff(encryptedMessage);
            case "aes":
                return encryptionService.aesDecryptOff(encryptedMessage);
            case "rsa":
                return encryptionService.rsaDecryptOff(encryptedMessage);
            default:
                throw new IllegalArgumentException("Invalid encryption_send method");
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody Map<String, String> request) throws Exception {
        String encryptedMessage = request.get("message");
        String method = request.get("method");
        String key = request.get("key");
        log.info("Decrypting message: '{}' with method: '{}'whith key: '{}'", encryptedMessage, method, key);
        switch (method.toLowerCase()) {
            case "caesar":
                int numberKey = Integer.parseInt(key);
                return encryptionService.caesarDecrypt(encryptedMessage, numberKey);
            case "aes":
                return encryptionService.aesDecrypt(encryptedMessage, key);
            case "rsa":
                return encryptionService.rsaDecrypt(encryptedMessage);
            default:
                throw new IllegalArgumentException("Invalid encryption method");
        }
    }
    @PostMapping("/decryptSEM")
    public String decryptSEM(@RequestBody Map<String, String> request) throws Exception {
        String encryptedMessage = request.get("message");
        String method = request.get("method");
        log.info("Decrypting message: '{}' with method: '{}", encryptedMessage, method);
        return "Received: " + encryptedMessage + " and method: " + method;

    }
    @PostMapping("/generate")
    public String generateKeysGEN(@RequestBody Map<String, String> request) throws Exception {
        String method = request.get("method");
        if( method.equals("rsa")){
            return "PUBKIC KEY: " + encryptionService.getPublicKey() + "\nPRIVATE KEY: " + encryptionService.getPrivateKey();
        } else if (method.equals("aes")) {
            return "AES KEY: " + encryptionService.getAesKeyOFF();
        }else{
            return "ERROR NOT FOUND METHOD";
        }

    }

    public String generateKeys(@RequestParam String method) throws Exception {
            this.privateKey = encryptionService.getPrivateKey();
            return encryptionService.getPublicKey();
    }
    @PostMapping("/send_public_key")
    public String SendKey(@RequestBody String method) throws Exception {
        String key = generateKeys(method);
        log.info("Sending key '{}' with method '{}'", key, method);
        return messageService.sendEncryptedMessage(method, key);
    }
    @PostMapping("/get_public_key")
    public String GetKey(@RequestBody Map<String, String> request) throws Exception {
        String method = request.get("method");
        String key = generateKeys(method);
        log.info("Sending key '{}' with method '{}'", key, method);
        return messageService.sendEncryptedMessage(method, key);
    }
}