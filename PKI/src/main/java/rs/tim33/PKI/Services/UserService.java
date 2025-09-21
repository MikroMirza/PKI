package rs.tim33.PKI.Services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import rs.tim33.PKI.Models.Role;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.UserRepository;
import rs.tim33.PKI.Utils.KeyHelper;

@Service
public class UserService {

	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private KeyHelper keyHelper;
	
	@Autowired
	private PasswordEncoder passEncoder;
	
	public UserModel registerEndUser(String email, String password, String name, String surname, String org) throws Exception {
		UserModel user = new UserModel();
		user.setEmail(email);
		//TODO: HASH THIS OR SMTH
		user.setPasswordHash(passEncoder.encode(password));
		user.setName(name);
		user.setSurname(surname);
		user.setOrganization(org);
		user.setRole(Role.USER);
		user.setKeystorePasswordEncrypted(keyHelper.generateEncryptedKeystoreKey());
		
		return userRepo.save(user);
	}
}
