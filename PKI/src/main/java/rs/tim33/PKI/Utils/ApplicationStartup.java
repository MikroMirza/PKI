package rs.tim33.PKI.Utils;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import rs.tim33.PKI.Models.Role;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.UserRepository;

@Component
public class ApplicationStartup {
	@Autowired
	private CertificateService certService;
	@Autowired
	private UserRepository userRepo;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@EventListener(ApplicationReadyEvent.class)
	public void onAppReady() throws Exception {
		try {
			UserModel admin = new UserModel();
			admin.setEmail("admin@example.com");
			admin.setName("Mirko");
			admin.setSurname("Hadzi Djukic");
			admin.setPasswordHash(passwordEncoder.encode("pass1234"));
			admin.setRole(Role.ADMIN);
			admin.setVerified(true);
			userRepo.save(admin);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
