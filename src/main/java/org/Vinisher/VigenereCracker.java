package org.Vinisher;

import java.util.*;

public class VigenereCracker extends Convert{

    private int gcd(int a, int b) {
        return b == 0 ? a : gcd(b, a % b);
    }

    private int gcd(List<Integer> distances) {
        int currentGCD = distances.get(0);
        for (int i = 1; i < distances.size(); i++) {
            currentGCD = gcd(currentGCD, distances.get(i));
        }
        return currentGCD;
    }


    private List<Integer> findRepeatedNGramDistances(String message, int nGramLength) {
        List<Integer> distances = new ArrayList<>();
        Map<String, List<Integer>> nGramPositions = new HashMap<>();

        for (int i = 0; i <= message.length() - nGramLength; i++) {
            String nGram = message.substring(i, i + nGramLength);
            nGramPositions.putIfAbsent(nGram, new ArrayList<>());
            nGramPositions.get(nGram).add(i);
        }

        for (List<Integer> positions : nGramPositions.values()) {
            for (int i = 0; i < positions.size() - 1; i++) {
                for (int j = i + 1; j < positions.size(); j++) {
                    distances.add(positions.get(j) - positions.get(i));
                }
            }
        }

        return distances;
    }

    public int findKeyLength(String message) {
        List<Integer> distances = findRepeatedNGramDistances(message, 3);
        if (distances.isEmpty()) return 0;

        Map<Integer, Integer> gcdCount = new HashMap<>();
        for (int i = 0; i < distances.size(); i++) {
            for (int j = i + 1; j < distances.size(); j++) {
                int gcd = gcd(distances.get(i), distances.get(j));
                if (gcd > 1) {
                    gcdCount.put(gcd, gcdCount.getOrDefault(gcd, 0) + 1);
                }
            }
        }

        return gcdCount.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(0);
    }

    public String crackKey(String message, int keyLength) {
        StringBuilder key = new StringBuilder();

        char[][] strings = new char[(message.length() / keyLength) + 1][keyLength];

        for (int i = 0; i < message.length(); i++) {
            int row = i / keyLength;
            int col = i % keyLength;
            strings[row][col] = message.charAt(i);
        }

        for (int i = 0; i < keyLength; i++) {
            Map<Character, Integer> frequencyMap = new HashMap<>();

            for (int j = 0; j < strings.length; j++) {
                if (strings[j][i] != 0) {
                    frequencyMap.put(strings[j][i], frequencyMap.getOrDefault(strings[j][i], 0) + 1);
                }
            }
            char mostFrequent = getMostFrequentChar(frequencyMap);
            int keyChar = (mostFrequent - 'e' + 26) % 26;
            key.append(criptoCtoN.get(keyChar));
        }

        return key.toString();
    }

    private char getMostFrequentChar(Map<Character, Integer> frequencyMap) {
        return Collections.max(frequencyMap.entrySet(), Map.Entry.comparingByValue()).getKey();
    }

public String crackVigenere(String message) {
    criptoCtoN = fillMap();
    int keyLength = findKeyLength(message);
    if (keyLength == 0) {
        return "The key length could not be determined.";
    }
    System.out.println("Key length: " + keyLength);
    String key = crackKey(message, keyLength);
    System.out.println("Found key: " + key);
    ArrayList<Integer> encodedMessage = encode(message);
    ArrayList<Integer> keyEncoded = encode(key);
    ArrayList<Integer> decoded = fullDecode(encodedMessage, keyEncoded);
    String decodedMessage = decode(decoded);
    return decodedMessage;
}


}
