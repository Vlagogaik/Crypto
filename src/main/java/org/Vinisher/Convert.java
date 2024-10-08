package org.Vinisher;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class Convert {
    HashMap<Integer, Character> criptoCtoN = new HashMap<>();

    public HashMap<Integer, Character> fillMap() {
        for (int i = 0; i <= 25; i++) {
            criptoCtoN.put(i, (char) ('a' + i));
        }
        return criptoCtoN;
    }

    public ArrayList<Integer> encode(String word) {
//        word = word.toUpperCase();
        word = word.toLowerCase();
        int lenght = word.length();
        ArrayList<Integer> list = new ArrayList<>();
        for (int i = 0; i <= lenght - 1; i++) {
            for (int j = 0; j <= 25; j++) {
                if (word.charAt(i) == criptoCtoN.get(j)) {
                    list.addLast(j);
                    j = 25;
                }
            }
        }
        return list;
    }

    private Map<Integer, int[]> comparator(ArrayList<Integer> word, ArrayList<Integer> key) {
        int len_key = key.size();
        int j = 0;
        Map<Integer, int[]> result = new HashMap<>();
        int iter = 0;

        for (Integer val : word) {
            result.put(j, new int[]{val, key.get(iter)});
            j++;
            iter++;
            if (iter >= len_key) {
                iter = 0;
            }
        }
        return result;
    }

    private ArrayList<Integer> fullEncode(ArrayList<Integer> word, ArrayList<Integer> key) {
        Map<Integer, int[]> dic = comparator(word, key);
        ArrayList<Integer> encodedList = new ArrayList<>();
        for (Map.Entry<Integer, int[]> entry : dic.entrySet()) {
            int[] pair = entry.getValue();
            int go = (pair[0] + pair[1]) % criptoCtoN.size();
            encodedList.add(go);
        }
        return encodedList;
    }
    public ArrayList<Integer> fullDecode(ArrayList<Integer> value, ArrayList<Integer> key) {
        Map<Integer, int[]> dic = comparator(value, key);
        ArrayList<Integer> decodedList = new ArrayList<>();
        for (Map.Entry<Integer, int[]> entry : dic.entrySet()) {
            int[] pair = entry.getValue();
            int go = (pair[0] - pair[1] + criptoCtoN.size()) % criptoCtoN.size();
            decodedList.add(go);
        }
        return decodedList;
    }

    public String decode(ArrayList<Integer> listIn) {
        StringBuilder decoded = new StringBuilder();
        for (Integer code : listIn) {
            decoded.append(criptoCtoN.get(code));
        }
        return decoded.toString();
    }

    public void vinisher(String word, String key){
        criptoCtoN = fillMap();
        System.out.println("Word: " + word);
        System.out.println("Key: " + key);

        ArrayList<Integer> keyEncoded = encode(key);
        ArrayList<Integer> wordEncoded = encode(word);

        System.out.println("Word encoded: " + wordEncoded);
        System.out.println("Key encoded: " + keyEncoded);

        ArrayList<Integer> cipher = fullEncode(wordEncoded, keyEncoded);
        System.out.println("Encode text: " + decode(cipher));

        ArrayList<Integer> decoded = fullDecode(cipher, keyEncoded);
//        System.out.println("Decode list: " + decoded);
        String decodedWord = decode(decoded);
        System.out.println("Decoded Word: " + decodedWord);
    }
    public String forCrack(String word, String key){
        criptoCtoN = fillMap();
        ArrayList<Integer> keyEncoded = encode(key);
        ArrayList<Integer> wordEncoded = encode(word);
        ArrayList<Integer> cipher = fullEncode(wordEncoded, keyEncoded);
        return decode(cipher);

    }
}
