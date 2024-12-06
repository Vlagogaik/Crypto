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
    private String publicRSAKey;
    private String privateRSAKey;
    private String keyAES;
    private String keyCaesar;
    private String encryptMessage;
    private String encryptMethod;

    public EncryptionController(EncryptionService encryptionService, MessageService messageService) {
        this.encryptionService = encryptionService;
        this.messageService = messageService;
    }
    @PostMapping("/send_encrypted_msg")
    public String sendEncryptedMessage(@RequestBody Map<String, String> request) throws Exception {
        if ((request.get("message") == null || request.get("method") == null) && (encryptMethod != null && encryptMessage != null)) {
            log.info("Sending encrypted LOCAL message: '{}' using method: '{}' ", encryptMessage, encryptMethod);
            return messageService.sendEncryptedMessageSEM(encryptMessage, encryptMethod);
        } else if ((encryptMethod == null || encryptMessage == null) && (request.get("message") != null || request.get("method") != null)) {
            String encryptedMessage = request.get("message");
            String method = request.get("method");
            log.info("Sending encrypted REQUEST message: '{}' using method: '{}' ", encryptedMessage, method);
            return messageService.sendEncryptedMessageSEM(encryptedMessage, method);
        }
        return "ERROR: 404 NOT FOUND MESSAGE OR METHOD";
    }
    @PostMapping("/get_public_key")
    public String getKey(@RequestBody Map<String, String> request) throws Exception {
        String method = request.get("method");
        switch (method.toLowerCase()) {
            case "rsa" -> {
                if (request.get("publickey") != null) {
                    this.publicRSAKey = request.get("publickey");
                    log.info("GET key '{}' with method '{}'", publicRSAKey, method);
                    return publicRSAKey;
                } else {
                    log.error("ERROR NOT GENERATED KEY OR KEY ALREADY EXISTS");
                    return "ERROR NOT GENERATED KEY OR KEY ALREADY EXISTS";
                }
            }
            case "aes" -> {
                if (request.get("publickey") != null) {
                    this.keyAES = request.get("publickey");
                    log.info("GET key '{}' with method '{}'", keyAES, method);
                    return keyAES;
                } else {
                    log.error("ERROR NOT GENERATED KEY OR KEY ALREADY EXISTS");
                    return "ERROR NOT GENERATED KEY OR KEY ALREADY EXISTS";
                }
            }
            case "caesar" -> {
                if (request.get("publickey") != null) {
                    this.keyCaesar = request.get("publickey");
                    log.info("GET key '{}' with method '{}'", keyCaesar, method);
                    return keyCaesar;
                } else {
                    log.error("ERROR NOT GENERATED KEY OR KEY ALREADY EXISTS");
                    return "ERROR NOT GENERATED KEY OR KEY ALREADY EXISTS";
                }
            }
            default -> {
                log.error("ERROR NOT FOUND METHOD");
                return "ERROR NOT FOUND METHOD";
            }
        }
    }
    @PostMapping("/encrypt")
    public String encryptOnly(@RequestBody Map<String, String> request) throws Exception {
        String message = request.get("message");
        String method = request.get("method");
        return switch (method.toLowerCase()) {
            case "caesar" -> {
                if (keyCaesar == null) {
                    log.error("ERROR NOT GENERATED CAESAR KEY");
                    yield "ERROR NOT GENERATED CAESAR KEY";
                }else{
                    this.encryptMessage = encryptionService.caesarEncrypt(message, Integer.parseInt(keyCaesar));
                    this.encryptMethod = "caesar";
                    log.info("Encrypting message: '{}' with method: '{}' whith key: '{}' ", message, method, keyCaesar);
                    yield encryptMessage;
                }
            }
            case "aes" -> {
                if (keyAES == null) {
                    log.error("ERROR NOT GENERATED AES KEY");
                    yield "ERROR NOT GENERATED AES KEY";
                }else {
                    this.encryptMessage = encryptionService.aesEncrypt(message, keyAES);
                    this.encryptMethod = "aes";
                    log.info("Encrypting message: '{}' with method: '{}' whith key: '{}' ", message, method, keyAES);
                    yield encryptionService.aesEncrypt(message, keyAES);
                }
            }
            case "rsa" -> {
                if (publicRSAKey == null) {
                    log.error("ERROR NOT GENERATED RSA KEY");
                    yield "ERROR NOT GENERATED RSA KEY";
                }else {
                    this.encryptMessage = encryptionService.rsaEncrypt(message, publicRSAKey);
                    this.encryptMethod = "rsa";
                    log.info("Encrypting message: '{}' with method: '{}' whith key: '{}' ", message, method, publicRSAKey);
                    yield encryptionService.rsaEncrypt(message, publicRSAKey);
                }
            }
            default -> throw new IllegalArgumentException("Invalid encryption method 000");
        };
    }

    @PostMapping("/encrypt_and_send")
    public String encryptAndSend(@RequestBody Map<String, String> request) throws Exception {
        messageService.sendGengerateKey(request.get("method"));
        return messageService.sendEncryptedMessage(encryptOnly(request) , request.get("method"));
    }
}
