package rs.tim33.PKI.Utils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

@Component
public class KeyHelper {

    @Value("${pki.master-key}")
    private String masterKeyBase64;

    private SecretKey masterKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Base64.getDecoder().decode(masterKeyBase64);
        masterKey = new SecretKeySpec(keyBytes, "AES");
    }

    public SecretKey getMasterKey() {
        return masterKey;
    }
    
    public SecretKey generateAESKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // 256-bit AES key
        return keyGen.generateKey();
    }
    
    private static final int IV_LENGTH = 12; // 96-bit IV for AES-GCM
    private static final int TAG_LENGTH = 128;

    public static String encrypt(SecretKey key, byte[] plaintext) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        // prepend IV to ciphertext
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);

        return Base64.getEncoder().encodeToString(combined);
    }

    public static byte[] decrypt(SecretKey key, String encrypted) throws Exception {
        byte[] combined = Base64.getDecoder().decode(encrypted);

        byte[] iv = new byte[IV_LENGTH];
        System.arraycopy(combined, 0, iv, 0, IV_LENGTH);

        byte[] ciphertext = new byte[combined.length - IV_LENGTH];
        System.arraycopy(combined, IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(ciphertext);
    }

    
    public String encodeBytes(byte[] key) {
    	return Base64.getEncoder().encodeToString(key);
    }
    
    public byte[] decodeBytes(String key) {
    	return Base64.getDecoder().decode(key);
    }
}