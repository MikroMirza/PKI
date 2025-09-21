package rs.tim33.PKI.Utils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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
    
    public SecretKey decryptKeystoreKey(byte[] encryptedKey) throws Exception {
//      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
//      cipher.init(Cipher.DECRYPT_MODE, masterKeyProvider.getMasterKey());
//      byte[] keyBytes = cipher.doFinal(encryptedKey);
      return new SecretKeySpec(encryptedKey, "AES");
    }
    
    public byte[] generateEncryptedKeystoreKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey orgMasterKey = keyGen.generateKey();
        return orgMasterKey.getEncoded();
    }
    
    //TODO
    public PrivateKey decryptPrivateKey(byte[] key, byte[] password) throws NoSuchAlgorithmException, InvalidKeySpecException {
    	PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
    
    public byte[] encryptPrivateKey(PrivateKey key, byte[] password) {
    	return key.getEncoded();
    }
    
    public String encodeBytes(byte[] key) {
    	return Base64.getEncoder().encodeToString(key);
    }
    
    public byte[] decodeBytes(String key) {
    	return Base64.getDecoder().decode(key);
    }
}