package rs.tim33.PKI.Services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import rs.tim33.PKI.Exceptions.ValidateArgumentsException;
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
	private VerificationService verificationService;
	@Autowired
	private PasswordEncoder passEncoder;
	
	public UserModel registerEndUser(String email, String password, String name, String surname, String org) throws Exception {
		validateArguments(email,password,name,surname,org);
		UserModel user = new UserModel();
		user.setEmail(email);
		//TODO: HASH THIS OR SMTH
		user.setPasswordHash(passEncoder.encode(password));
		user.setName(name);
		user.setSurname(surname);
		user.setOrganization(org);
		user.setRole(Role.USER);
		user.setKeystorePasswordEncrypted(keyHelper.generateEncryptedKeystoreKey());
		user = userRepo.save(user);
		
		verificationService.sendVerificationEmail(user);
		return userRepo.save(user);
	}
	
	
	//No email verification here :)
	public UserModel registerCaUser(String email, String password, String name, String surname, String org) throws Exception {
		validateArguments(email,password,name,surname,org);
		UserModel user = new UserModel();
		user.setEmail(email);
		user.setPasswordHash(passEncoder.encode(password));
		user.setName(name);
		user.setSurname(surname);
		user.setOrganization(org);
		user.setRole(Role.CA);
		user.setKeystorePasswordEncrypted(keyHelper.generateEncryptedKeystoreKey());
		
		return userRepo.save(user);
	}
	
	private void validateArguments(String email, String password, String name, String surname, String org) {
		if (email == null) {
			throw new ValidateArgumentsException("Email must be provided.","EMPTY_EMAIL_ERROR");
		}
		if (password == null) {
			throw new ValidateArgumentsException("Password must be provided.","EMPTY_PASSWORD_ERROR");		
			}
		if (name == null) {
			throw new ValidateArgumentsException("Name must be provided.","EMPTY_NAME_ERROR");
		}
		if (surname == null) {
			throw new ValidateArgumentsException("Surname must be provided.","EMPTY_SURNAME_ERROR");
		}
		if (org == null) {
			throw new ValidateArgumentsException("Organization must be provided.","EMPTY_ORG_ERROR");
		}
		if (!email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$")) {
		    throw new ValidateArgumentsException("Invalid email format. \n(ex. example@gmail.com)", "INVALID_EMAIL_ERROR");
		}
		if (!password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{6,}$")) {
		    throw new ValidateArgumentsException(
		        "Password must be at least 6 characters long and contain uppercase, lowercase, number, and special character. \n (ex. aA$123)",
		        "INVALID_PASSWORD_ERROR"
		    );
		}
		if (!name.matches("^[A-Za-z]{2,}$")) {
		    throw new ValidateArgumentsException("Name must be at least 2 letters, letters only.", "INVALID_NAME_ERROR");
		}
		if (!surname.matches("^[A-Za-z]{2,}$")) {
		    throw new ValidateArgumentsException("Surname must be at least 2 letters, letters only.", "INVALID_SURNAME_ERROR");
		}
		if (!org.matches("^[A-Za-z0-9\\s-]{3,}$")) {
		    throw new ValidateArgumentsException("Organization must be at least 3 characters, letters/numbers/spaces only.", "INVALID_ORG_ERROR");
		}
		
	}
	
	
}
