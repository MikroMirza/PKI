package rs.tim33.PKI.Services;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import rs.tim33.PKI.Models.AliasKey;
import rs.tim33.PKI.Repositories.KeystoreRepository;
import rs.tim33.PKI.Utils.KeyHelper;

@Service
public class KeystoreService {
	@Autowired
	private KeystoreRepository keyRepo;
	@Autowired
	private KeyHelper keyHelper;
	
	private byte[] generateKey(String alias) {
		try {
			AliasKey ak = new AliasKey();
			byte[] key = keyHelper.generateEncryptedKeystoreKey();
			ak.setAlias(alias);
			ak.setEncryptedKey(key);
			keyRepo.save(ak);
			return key;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public byte[] exportAsPKCS12(PrivateKey privateKey, X509Certificate certificate, String alias, String password) throws Exception {
	    KeyStore ks = KeyStore.getInstance("PKCS12");
	    ks.load(null, password.toCharArray());

	    ks.setKeyEntry(alias, privateKey, password.toCharArray(), new Certificate[]{certificate});

	    ByteArrayOutputStream baos = new ByteArrayOutputStream();
	    ks.store(baos, password.toCharArray());
	    return baos.toByteArray();
	}

	
	
	public byte[] getEncryptedOrganizationKey(String orgName) {
		return keyRepo.findByAlias(orgName).map(t -> t.getEncryptedKey()).orElseGet(() -> generateKey(orgName));
	}
	
	public byte[] getEncryptedKeyFromAlias(String alias) {
		return keyRepo.findByAlias(alias).map(t -> t.getEncryptedKey()).orElseGet(() -> generateKey(alias));
	}
}
