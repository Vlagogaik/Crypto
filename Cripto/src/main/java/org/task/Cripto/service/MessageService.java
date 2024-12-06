package org.task.Cripto.service;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class MessageService {
    private final RestTemplate restTemplate = new RestTemplate();

    public String sendEncryptedMessage(String message, String method) {
        String url = "http://localhost:8081/api/decrypt";
        var request = new HashMap<String, String>();
        request.put("message", message);
        request.put("method", method);
//        request.put("key", key);
        return restTemplate.postForObject(url, request, String.class);
    }
    public String sendEncryptedMessageSEM(String message, String method) {
        String url = "http://localhost:8081/api/save_encrypt_mes";
        var request = new HashMap<String, String>();
        request.put("message", message);
        request.put("method", method);
        return restTemplate.postForObject(url, request, String.class);
    }
    public String sendGengerateKey(String method) {
        postGenerateKey(method);
        String url = "http://localhost:8081/api/send_public_key";
        Map<String, String> request = new HashMap<>();
        request.put("method", method);
        String publicKey = restTemplate.postForObject(url, request, String.class);
        return publicKey;
    }
    public String postGenerateKey(String method) {
        String urlGen = "http://localhost:8081/api/generate";
        Map<String, String> request = new HashMap<>();
        request.put("method", method);
        String publicKey = restTemplate.postForObject(urlGen, request, String.class);
        return publicKey;
    }

}

