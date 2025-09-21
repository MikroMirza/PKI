package rs.tim33.PKI.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import rs.tim33.PKI.DTO.Auth.LoginDTO;
import rs.tim33.PKI.Utils.JwtUtils;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	private AuthenticationManager authManager;
	@Autowired
	private JwtUtils jwtUtils;
	
	@PostMapping("/login")
	public String login(@RequestBody LoginDTO data){
		Authentication authentication = authManager.authenticate(new UsernamePasswordAuthenticationToken(data.email, data.password));
		UserDetails user = (UserDetails)authentication.getPrincipal();
		return jwtUtils.generateToken(user.getUsername());
	}
}
