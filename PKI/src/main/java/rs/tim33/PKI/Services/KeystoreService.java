package rs.tim33.PKI.Services;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import rs.tim33.PKI.Models.CertificateModel;
import rs.tim33.PKI.Models.KeystoreModel;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.CertificateRepository;
import rs.tim33.PKI.Repositories.KeystoreRepository;
import rs.tim33.PKI.Utils.CertificateHelper;
import rs.tim33.PKI.Utils.CertificateService;
import rs.tim33.PKI.Utils.KeyHelper;

@Service
public class KeystoreService {
	@Autowired
    private KeystoreRepository keystoreRepository;
	
	@Autowired
    private CertificateRepository certRepo;

    
    @Autowired
    private KeyHelper keyHelper;
    
    public KeyStore getKeystoreFromId(Long keystoreId) throws Exception {
    	KeystoreModel ks = keystoreRepository.findById(keystoreId).orElse(null);
    	//TODO: Decrypt
    	String keystorePassword = keyHelper.encodeKey(keyHelper.decryptKeystoreKey(ks.getPasswordEncrypted()).getEncoded());
        KeyStore keyStore = KeyStore.getInstance(ks.getKeystoreType());

        try (ByteArrayInputStream bais = new ByteArrayInputStream(ks.getKeystoreData())) {
            keyStore.load(bais, keystorePassword.toCharArray());
        }
        return keyStore;
    }
    
    public KeystoreModel saveKeystoreWithId(Long keystoreId, KeyStore keystore) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
    	KeystoreModel ks = keystoreRepository.findById(keystoreId).orElse(null);
    	String keystorePassword = keyHelper.encodeKey(ks.getPasswordEncrypted());
    	
    	try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
    		keystore.store(baos, keystorePassword.toCharArray());
            ks.setKeystoreData(baos.toByteArray());
        }
    	
    	return keystoreRepository.save(ks);
    }

    public KeystoreModel addCertificate(Long keystoreId, Long cetificateId, PrivateKey privateKey) throws Exception {
    	CertificateModel cert = certRepo.findById(cetificateId).orElse(null);
    	
        //Get keystore
    	KeyStore keystore = getKeystoreFromId(keystoreId);
    	
    	//Add certificate
        X509Certificate ctf = CertificateHelper.getX509Certificate(cert.getCertData());
        keystore.setKeyEntry(cert.getAlias() + "_" + cert.getSerialNumber(), privateKey, "TODO PASSWORD".toCharArray(), new Certificate[] {ctf});
        
        //Persist to database
        return saveKeystoreWithId(keystoreId, keystore);
    }
    
    //Alias - keystore name (must be unique)
    //keystorePassword - decrypted password
    public KeystoreModel createKeystore(String alias, byte[] keystorePassword) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        String passwordString = keyHelper.encodeKey(keystorePassword);
        keyStore.store(baos, passwordString.toCharArray());

        byte[] encryptedPassword = keystorePassword;

        KeystoreModel ks = new KeystoreModel();
        ks.setAlias(alias);
        ks.setKeystoreType("PKCS12");
        ks.setKeystoreData(baos.toByteArray());
        ks.setPasswordEncrypted(encryptedPassword);

        return keystoreRepository.save(ks);
    }
    
    public KeystoreModel createKeystoreForUser(UserModel user) throws Exception{
    	return createKeystore("ENDUSER_" + user.getEmail(), keyHelper.decryptKeystoreKey(user.getKeystorePasswordEncrypted()).getEncoded());
    }
    
    public KeystoreModel findKeystoreForUser(UserModel user) {
    	return keystoreRepository.findByAlias("ENDUSER_" + user.getEmail()).orElse(null);
    }
    
    public boolean keystoreExists(String alias) {
    	return keystoreRepository.findByAlias(alias).isPresent();
    }
}
