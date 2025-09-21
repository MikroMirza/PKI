package rs.tim33.PKI.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
import rs.tim33.PKI.DTO.Auth.LoginResponse;
import rs.tim33.PKI.DTO.Auth.RefreshRequest;
import rs.tim33.PKI.DTO.Auth.RefreshResponse;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.RefreshTokenRepository;
import rs.tim33.PKI.Repositories.UserRepository;
import rs.tim33.PKI.Services.RefreshTokenService;
import rs.tim33.PKI.Utils.JwtUtils;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
	@Autowired
	private RefreshTokenRepository refreshRepo;
	
	@Autowired
	private RefreshTokenService refreshService;
	
	@Autowired
	private AuthenticationManager authManager;
	@Autowired
	private JwtUtils jwtUtils;
	
	@Autowired
	private UserRepository userRepo;
	
	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login(@RequestBody LoginDTO data){
		Authentication authentication = authManager.authenticate(new UsernamePasswordAuthenticationToken(data.email, data.password));
		UserDetails user = (UserDetails)authentication.getPrincipal();
		
		UserModel u = userRepo.findByEmail(data.email).orElse(null);
		if(u == null)
			return ResponseEntity.notFound().build();
		
		LoginResponse data2 = new LoginResponse();
		data2.jwt = jwtUtils.generateToken(u.getEmail(), u.getRole());
		data2.refresh = refreshService.createRefreshToken(user.getUsername()).getToken();
		data2.role = u.getRole().toString();
		System.out.println("ALOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOO " + u.getRole().toString());
		
		return ResponseEntity.ok(data2);
	}
	
	@PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshRequest data) {
        return refreshRepo.findByToken(data.token)
            .map(token -> {
                if (refreshService.isTokenExpired(token)) {
                    refreshRepo.delete(token);
                    return ResponseEntity.badRequest().body("Refresh token expired. Please login again.");
                }
                String newJwt = jwtUtils.generateToken(token.getUser().getEmail(), token.getUser().getRole());
                RefreshResponse resp = new RefreshResponse();
                resp.jwt = newJwt;
                return ResponseEntity.ok(resp);
            })
            .orElseGet(() -> ResponseEntity.badRequest().body("Invalid refresh token."));
    }
	
	@PostMapping("/logout")
    public ResponseEntity<?> logoutUser(@RequestBody RefreshRequest data) {
        String requestToken = data.token;

        if (requestToken == null || requestToken.isBlank()) {
            return ResponseEntity.badRequest().body("Refresh token is required.");
        }

        return refreshRepo.findByToken(requestToken)
                .map(token -> {
                	refreshRepo.delete(token);
                    return ResponseEntity.ok("Logged out successfully.");
                })
                .orElse(ResponseEntity.badRequest().body("Invalid refresh token."));
    }
}
