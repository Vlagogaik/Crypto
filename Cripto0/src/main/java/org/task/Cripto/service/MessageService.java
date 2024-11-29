package org.task.Cripto.service;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.util.HashMap;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class MessageService {
    private final RestTemplate restTemplate = new RestTemplate();

    public String sendEncryptedMessage(String method, String key) {
        String url = "http://localhost:8080/api/get_public_key";
        var request = new HashMap<String, String>();
        request.put("method", method);
        request.put("publickey", key);
        return restTemplate.postForObject(url, request, String.class);
    }
}

