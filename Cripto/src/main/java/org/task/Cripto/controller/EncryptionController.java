package org.task.Cripto.controller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.task.Cripto.service.EncryptionService;
import org.task.Cripto.service.MessageService;

import javax.crypto.SecretKey;
import java.util.Map;
import java.util.Random;

@RestController
@RequestMapping("/api")
public class EncryptionController {
    private static final Logger log = LoggerFactory.getLogger(EncryptionController.class);
    private final EncryptionService encryptionService;
    private final MessageService messageService;
    private String publicKey;

    public EncryptionController(EncryptionService encryptionService, MessageService messageService) {
        this.encryptionService = encryptionService;
        this.messageService = messageService;
    }
    @PostMapping("/get_public_key")
    public String getKey(@RequestBody Map<String, String> request) throws Exception {
        this.publicKey = request.get("publickey");
        return  publicKey;
    }
    @PostMapping("/encrypt")
    public String encryptOnly(@RequestBody Map<String, String> request) throws Exception {
        String message = request.get("message");
        String method = request.get("method");
        String key;
        switch (method.toLowerCase()) {
            case "caesar":
                Random random = new Random();
                int randomNumber = random.nextInt(26) + 1;
                log.info("Encrypting message: '{}' with method: '{}' whith key: '{}' ", message, method, randomNumber);
                return encryptionService.caesarEncrypt(message, randomNumber);
            case "aes":
                key = encryptionService.getAesKeyOFF();
                log.info("Encrypting message: '{}' with method: '{}' whith key: '{}' ", message, method, key);
                return encryptionService.aesEncrypt(message, key);
            case "rsa":
                key = encryptionService.getPublicKey();
                log.info("Encrypting message: '{}' with method: '{}' whith key: '{}' ", message, method, key);
                return encryptionService.rsaEncrypt(message, key);
            default:
                throw new IllegalArgumentException("Invalid encryption method 000");
        }
    }

    public String encrypt(@RequestBody Map<String, String> request, String key) throws Exception {
        String message = request.get("message");
        String method = request.get("method");

//        log.info("Encrypting message: '{}' with method: '{}' whith key: '{}' ", message, method, key);
        switch (method.toLowerCase()) {
            case "caesar":
                int numberKey = Integer.parseInt(key);
                return encryptionService.caesarEncrypt(message, numberKey);
            case "aes":
                return encryptionService.aesEncrypt(message, key);
            case "rsa":
                return encryptionService.rsaEncrypt(message, key);
            default:
                throw new IllegalArgumentException("Invalid encryption method 000");
        }
    }

    @GetMapping("/generate")
    public String generateKeys(@RequestParam String method) throws Exception {
            if(method.toLowerCase().equals("rsa")){
                return "Open RSA key: " + messageService.sendGengerateKey("rsa");
            } else if (method.toLowerCase().equals("aes")) {
                return encryptionService.getAesKeyOFF();
            }
        return "ERROR: Not found method!";
    }
    @PostMapping("/encrypt_and_send")
    public String encryptAndSend(@RequestBody Map<String, String> request) throws Exception {
        String message = request.get("message");
        String method = request.get("method");

//        log.info("Encrypting and sending message '{}' with method '{}'", message, method);
        switch (method.toLowerCase()) {
            case "caesar":
                Random random = new Random();
                int randomNumber = random.nextInt(26) + 1;
                String key0 = String.valueOf(randomNumber);
                log.info("CASE caesar with message '{}' with method '{}' and key '{}'", message, method, key0);
                return messageService.sendEncryptedMessage(encrypt(request, key0), method, key0);
            case "aes":
                String aesKey = encryptionService.getAesKey(messageService.sendGengerateKey("rsa"));
                log.info("CASE AES with message '{}' with method '{}' and key '{}'", message, method, aesKey);
                return messageService.sendEncryptedMessage(encrypt(request, null), method, aesKey);
            case "rsa":
                String key = messageService.sendGengerateKey(method.toLowerCase());
                log.info("CASE AES with message '{}' with method '{}' and key '{}'", message, method);
                return messageService.sendEncryptedMessage(encrypt(request, key), method, null);
            default:
                throw new IllegalArgumentException("Invalid encryption_send method");
        }
    }


}
