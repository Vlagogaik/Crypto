package org.task.Cripto.controller;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;
import org.task.Cripto.service.EncryptionService;
import org.task.Cripto.service.MessageService;

import java.util.Map;

//@Slf4j
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

    @PostMapping("/get_encrypted_msg ")
    public String SendCryptoMessage(@RequestBody Map<String, String> request) throws Exception {
        if((encryptMessage == null || encryptMethod == null) || request.get("message") != null){
            if(request.get("message") != null && request.get("method")!= null){
                String encryptedMessage = request.get("message");
                String method = request.get("method");
                log.info("Decrypting message WITHOUT local data: '{}' with method: '{}'", encryptedMessage, method);
                return switch (method.toLowerCase()) {
                    case "caesar" -> encryptionService.caesarDecrypt(encryptedMessage, Integer.parseInt(keyCaesar));
                    case "aes" -> encryptionService.aesDecrypt(encryptedMessage, keyAES);
                    case "rsa"-> encryptionService.rsaDecrypt(encryptedMessage);
                    default -> throw new IllegalArgumentException("Invalid encryption_send method");
                };
            }else{
                log.error("ERROR NOT FOUND MESSAGE OR METHOD");
                return "ERROR NOT FOUND MESSAGE OR METHOD";
            }
        }else {
            if(encryptMessage == null || encryptMethod == null){
                log.error("ERROR NOT FOUND MESSAGE OR METHOD");
                return "ERROR NOT FOUND MESSAGE OR METHOD";
            }else {
                log.info("Decrypting message WITH local data: '{}' with method: '{}'", encryptMessage, encryptMethod);
                return switch (encryptMethod.toLowerCase()) {
                    case "caesar" -> encryptionService.caesarDecrypt(encryptMessage, Integer.parseInt(keyCaesar));
                    case "aes" -> encryptionService.aesDecrypt(encryptMessage, keyAES);
                    case "rsa" -> encryptionService.rsaDecrypt(encryptMessage);
                    default -> throw new IllegalArgumentException("Invalid encryption_send method");
                };
            }
        }
    }

    @PostMapping("/decrypt")
    public String decrypt(@RequestBody Map<String, String> request) throws Exception {
        String encryptedMessage = request.get("message");
        String method = request.get("method");
        log.info("Decrypting message: '{}' with method: '{}'", encryptedMessage, method);
        switch (method.toLowerCase()) {
            case "caesar":
                int numberKey = Integer.parseInt(keyCaesar);
                return encryptionService.caesarDecrypt(encryptedMessage, numberKey);
            case "aes":
                return encryptionService.aesDecrypt(encryptedMessage, keyAES);
            case "rsa":
                return encryptionService.rsaDecrypt(encryptedMessage);
            default:
                throw new IllegalArgumentException("Invalid encryption method");
        }
    }
    @PostMapping("/save_encrypt_mes")
    public String save(@RequestBody Map<String, String> request){
        this.encryptMessage = request.get("message");
        this.encryptMethod = request.get("method");
        log.info("Getting message: '{}' with method: '{}", encryptMessage, encryptMethod);
        return "Received: " + encryptMessage + " and method: " + encryptMethod;

    }
    @PostMapping("/generate")
    public String generateKeys(@RequestBody Map<String, String> request) throws Exception {
        String method = request.get("method");
        switch (method.toLowerCase()) {
            case "rsa" -> {
                this.privateRSAKey = encryptionService.getPrivateKey();
                this.publicRSAKey = encryptionService.getPublicKey();
                return publicRSAKey;
            }
            case "aes" -> {
                this.keyAES = encryptionService.getAesKeyOFF();
                return keyAES;
            }
            case "caesar" -> {
                this.keyCaesar = encryptionService.getCaesatKey();
                return keyCaesar;
            }
            default -> {
                return "ERROR NOT FOUND METHOD";
            }
        }
    }

    @PostMapping("/send_public_key")
    public String SendKey(@RequestBody Map<String, String> request) throws Exception {
        String method = request.get("method");
        switch (method.toLowerCase()) {
            case "rsa" -> {
                if (publicRSAKey != null) {
                    log.info("Sending key '{}' with method '{}'", publicRSAKey, method);
                    return messageService.sendEncryptedMessage(method, publicRSAKey);
                } else {
                    log.error("ERROR NOT GENERATED KEY");
                    return "ERROR NOT GENERATED KEY";
                }
            }
            case "aes" -> {
                if (keyAES != null) {
                    log.info("Sending key '{}' with method '{}'", keyAES, method);
                    return messageService.sendEncryptedMessage(method, keyAES);
                } else {
                    log.error("ERROR NOT GENERATED KEY");
                    return "ERROR NOT GENERATED KEY";
                }
            }
            case "caesar" -> {
                if (keyCaesar != null) {
                    log.info("Sending key '{}' with method '{}'", keyCaesar, method);
                    return messageService.sendEncryptedMessage(method, keyCaesar);
                } else {
                    log.error("ERROR NOT GENERATED KEY");
                    return "ERROR NOT GENERATED KEY";
                }
            }
            default -> {
                log.error("ERROR NOT FOUND METHOD");
                return "ERROR NOT FOUND METHOD";
            }
        }
    }

}