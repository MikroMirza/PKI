package rs.tim33.PKI.Services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import rs.tim33.PKI.DTO.Auth.LoginResponse;
import rs.tim33.PKI.Exceptions.LoginException;
import rs.tim33.PKI.Exceptions.ValidateArgumentsException;
import rs.tim33.PKI.Models.Role;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.RefreshTokenRepository;
import rs.tim33.PKI.Repositories.UserRepository;
import rs.tim33.PKI.Utils.JwtUtils;
import rs.tim33.PKI.Utils.KeyHelper;

@Service
public class AuthService {
	@Autowired
	private UserRepository userRepo;
	@Autowired
	private RefreshTokenRepository refreshRepo;
	
	@Autowired
	private RefreshTokenService refreshService;
	@Autowired
	private JwtUtils jwtUtils;
	
	public LoginResponse getLoginResponse(UserModel user, String username) {
		
		if(user == null)
			throw new LoginException("User with that Email doesn't exist","EMAIL_NULL");
		if(!user.isVerified())
			throw new LoginException("The user didn't verify","EMAIL_NULL");
		
		
		LoginResponse loginResp = new LoginResponse();
		loginResp.jwt = jwtUtils.generateToken(user.getEmail(), user.getRole());
		loginResp.refresh = refreshService.createRefreshToken(username).getToken();
		loginResp.role = user.getRole().toString();
		
		return loginResp;
	}
}
