package rs.tim33.PKI.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import rs.tim33.PKI.DTO.User.RegisterUserDTO;
import rs.tim33.PKI.DTO.Verification.VerificationResponse;
import rs.tim33.PKI.Exceptions.VerificationTokenException;
import rs.tim33.PKI.Services.UserService;
import rs.tim33.PKI.Services.VerificationService;

@RestController
@RequestMapping("/api/users")
public class UserController {
	@Autowired
	private UserService userService;
	@Autowired
	private VerificationService verificationService;
	
	@PostMapping("/regular")
	public ResponseEntity<Void> registerRegularUser(@RequestBody RegisterUserDTO data){
		try {
			userService.registerEndUser(data.email, data.password, data.name, data.surname, data.organization);
		} catch (Exception e) {
			e.printStackTrace();
			return new ResponseEntity<Void>(HttpStatus.BAD_REQUEST);
		}
		
		return new ResponseEntity<Void>(HttpStatus.OK);
	}
	
	@GetMapping("/verification")
	public ResponseEntity<VerificationResponse> verifyUser(@RequestParam("token") String token) {
	    try {
	    	verificationService.verify(token);
	        return ResponseEntity.ok(new VerificationResponse(true, "User verified successfully", null));
	    } catch (VerificationTokenException ex) {
	        return ResponseEntity
	                .badRequest()
	                .body(new VerificationResponse(false, ex.getMessage(), ex.getErrorCode()));
	    } catch (Exception ex) {
	        ex.printStackTrace();
	        return ResponseEntity
	                .status(HttpStatus.INTERNAL_SERVER_ERROR)
	                .body(new VerificationResponse(false, "Unexpected error", "INTERNAL_ERROR"));
	    }
	}

}
