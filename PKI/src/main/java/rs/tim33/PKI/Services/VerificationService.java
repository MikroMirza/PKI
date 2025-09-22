package rs.tim33.PKI.Services;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import rs.tim33.PKI.Exceptions.VerificationTokenException;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Models.VerificationToken;
import rs.tim33.PKI.Repositories.UserRepository;
import rs.tim33.PKI.Repositories.VerificationTokenRepository;

@Service
public class VerificationService {

    @Autowired
    private VerificationTokenRepository tokenRepo;

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private JavaMailSender mailSender;

    public void sendVerificationEmail(UserModel user) {
        String token = UUID.randomUUID().toString();

        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setToken(token);
        verificationToken.setUserId(user.getId());

        // expire in 24h
        verificationToken.setExpirationDate(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24));

        tokenRepo.save(verificationToken);

        String verificationUrl = "http://localhost:4200/authentication/verification?token=" + token;
//        String verificationUrl = "http://192.168.2.8:8080/api/verify?token=" + token;

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(user.getEmail());
        message.setFrom("mirkodjukic23@gmail.com");
        message.setSubject("Account Verification");
        message.setText("Click the link to verify your account:\n\n" + verificationUrl);

        mailSender.send(message);
    }

    @Transactional
    public void verify(String decodedToken) {
        Optional<VerificationToken> optionalToken = tokenRepo.findByToken(decodedToken);
        if (optionalToken.isEmpty()) {
            throw new VerificationTokenException("Invalid token.", "INVALID_TOKEN");
        }

        VerificationToken verificationToken = optionalToken.get();
        if (verificationToken.getExpirationDate().before(new Date())) {
            throw new VerificationTokenException("Token expired.", "TOKEN_EXPIRED");
        }

        Optional<UserModel> optUser = userRepo.findById(verificationToken.getUserId());
        if (optUser.isEmpty()) {
            throw new VerificationTokenException("No user", "BAD_TOKEN");
        }
        
        UserModel user = optUser.get();
        if(user.isVerified()==true) {
        	throw new VerificationTokenException("This user is already verified", "ALREADY_VERIFIED");
        }
        user.setVerified(true);
        userRepo.save(user);
    }
}
