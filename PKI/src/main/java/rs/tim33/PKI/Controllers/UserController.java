package rs.tim33.PKI.Controllers;

import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.persistence.EntityNotFoundException;
import jakarta.websocket.server.PathParam;
import rs.tim33.PKI.DTO.Certificate.SimpleCertificateDTO;
import rs.tim33.PKI.DTO.User.RegisterUserDTO;
import rs.tim33.PKI.DTO.Verification.VerificationResponse;
import rs.tim33.PKI.Exceptions.ErrorMessage;
import rs.tim33.PKI.Exceptions.ValidateArgumentsException;
import rs.tim33.PKI.Exceptions.VerificationTokenException;
import rs.tim33.PKI.Models.Role;
import rs.tim33.PKI.Models.UserModel;
import rs.tim33.PKI.Repositories.UserRepository;
import rs.tim33.PKI.Services.UserService;
import rs.tim33.PKI.Services.VerificationService;
import rs.tim33.PKI.Utils.CertificateService;
import rs.tim33.PKI.Utils.LoggedUserUtils;

@RestController
@RequestMapping("/api/users")
public class UserController {
	@Autowired
	private UserRepository userRepo;
	@Autowired
	private UserService userService;
	@Autowired
	private VerificationService verificationService;
	@Autowired
	private CertificateService certService;
	@Autowired
	private LoggedUserUtils loggedUserUtils;
	
	@PostMapping("/regular")
	public ResponseEntity<?> registerRegularUser(@RequestBody RegisterUserDTO data){
		try {
			userService.registerEndUser(data.email, data.password, data.name, data.surname, data.organization);
	    } catch (ValidateArgumentsException ex) {
	        return ResponseEntity
	                .badRequest()
	                .body(new ErrorMessage(ex.getMessage(), ex.getErrorCode()));
	    } catch (Exception e) {
	        e.printStackTrace();
	        return ResponseEntity
	                .status(HttpStatus.INTERNAL_SERVER_ERROR)
	                .body(new ErrorMessage("Unexpected error", "INTERNAL_ERROR"));
	    }
		
        return ResponseEntity.ok().build();
	}
	
	@PostMapping("/ca")
	public ResponseEntity<?> registerCaUser(@RequestBody RegisterUserDTO data){
	    try {
	        userService.registerCaUser(data.email, data.password, data.name, data.surname, data.organization);
	        return ResponseEntity.ok().build();
	    } catch (ValidateArgumentsException ex) {
	        return ResponseEntity
	                .badRequest()
	                .body(new ErrorMessage(ex.getMessage(), ex.getErrorCode()));
	    } catch (Exception e) {
	        e.printStackTrace();
	        return ResponseEntity
	                .status(HttpStatus.INTERNAL_SERVER_ERROR)
	                .body(new ErrorMessage("Unexpected error", "INTERNAL_ERROR"));
	    }
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

	@PostMapping("/{userId}/certificates")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> giveUserCertificate(@PathParam("userId") Long userId, @RequestParam("certId") Long certId){
		try {
			userService.giveUserCertificate(userId, certId);
		} catch (EntityNotFoundException e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorMessage(e.getMessage(), "ERR_NOT_FOUND"));
		} catch (BadRequestException e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage(e.getMessage(), "ERR_BAD_ARG"));
		}
		
		return ResponseEntity.status(HttpStatus.OK).body("Success");
	}
	
	
	@DeleteMapping("/{userId}/certificates/{certId}")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> removeUsersCertificate(@PathParam("userId") Long userId, @PathParam("certId") Long certId){
		try {
			userService.removeUsersCertificate(userId, certId);
		} catch (EntityNotFoundException e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorMessage(e.getMessage(), "ERR_NOT_FOUND"));
		}
		
		return ResponseEntity.status(HttpStatus.OK).body("Success");
	}
	
	@GetMapping("/{userId}/certificates")
	public ResponseEntity<?> getUsersCertificates(@PathParam("userId") Long userId){
		UserModel loggedUser = loggedUserUtils.getLoggedInUser();
		if(loggedUser == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorMessage("Please log in", "ERR_UNATUH"));
		if(loggedUser.getRole() != Role.ADMIN || loggedUser.getId() != userId)
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorMessage("Access denied", "ERR_FORBIDDEN"));
		
		UserModel user = userRepo.findById(userId).orElse(null);
		if(user == null)
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new ErrorMessage("User not found", "ERR_NOT_FOUND"));
		
		return ResponseEntity.status(HttpStatus.OK).body(certService.getUsersCertificates(user).stream().map(c -> new SimpleCertificateDTO(c)).toList());
	}
}
