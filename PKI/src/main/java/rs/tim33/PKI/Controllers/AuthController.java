package rs.tim33.PKI.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
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
import rs.tim33.PKI.Exceptions.ErrorMessage;
import rs.tim33.PKI.Exceptions.LoginException;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.RefreshTokenRepository;
import rs.tim33.PKI.Repositories.UserRepository;
import rs.tim33.PKI.Services.AuthService;
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
	
	@Autowired
	private AuthService authService;
	
	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody LoginDTO data) {
	    try {
	        Authentication authentication = authManager.authenticate(
	            new UsernamePasswordAuthenticationToken(data.email, data.password)
	        );
	        UserDetails user = (UserDetails) authentication.getPrincipal();

	        UserModel u = userRepo.findByEmail(data.email).orElse(null);
	        LoginResponse loginResp = authService.getLoginResponse(u, user.getUsername());

	        return ResponseEntity.ok(loginResp);

	    } catch (LoginException ex) {
	        return ResponseEntity
	                .status(HttpStatus.UNAUTHORIZED)
	                .body(new ErrorMessage(ex.getMessage(), ex.getErrorCode()));
	    } catch (BadCredentialsException ex) {
	        return ResponseEntity
	                .status(HttpStatus.UNAUTHORIZED)
	                .body(new ErrorMessage("Invalid email or password", "INVALID_CREDENTIALS"));
	    } catch (Exception ex) {
	        ex.printStackTrace();
	        return ResponseEntity
	                .status(HttpStatus.INTERNAL_SERVER_ERROR)
	                .body(new ErrorMessage("Unexpected error", "INTERNAL_ERROR"));
	    }
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
