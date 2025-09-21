package rs.tim33.PKI.Services;

import java.security.NoSuchAlgorithmException;

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
	
	public byte[] getEncryptedOrganizationKey(String orgName) {
		return keyRepo.findByAlias(orgName).map(t -> t.getEncryptedKey()).orElseGet(() -> generateKey(orgName));
	}
	
	public byte[] getEncryptedKeyFromAlias(String alias) {
		return keyRepo.findByAlias(alias).map(t -> t.getEncryptedKey()).orElseGet(() -> generateKey(alias));
	}
}
