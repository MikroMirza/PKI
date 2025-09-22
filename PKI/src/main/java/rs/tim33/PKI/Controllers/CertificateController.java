package rs.tim33.PKI.Controllers;

import java.util.List;

import javax.security.sasl.AuthenticationException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import rs.tim33.PKI.DTO.Certificate.CreateCertificateDTO;
import rs.tim33.PKI.DTO.Certificate.SimpleCertificateDTO;
import rs.tim33.PKI.Exceptions.ErrorMessage;
import rs.tim33.PKI.Exceptions.InvalidCertificateRequestException;
import rs.tim33.PKI.Exceptions.InvalidIssuerException;
import rs.tim33.PKI.Utils.CertificateService;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {
	@Autowired
	private CertificateService certService;
	
	@PostMapping("/intermediate")
	public ResponseEntity<?> createIntermediate(@RequestBody CreateCertificateDTO data){
		try {
			certService.createCertificate(data.issuerId, data.cn, data.organization, data.organizationUnit, data.notBefore, data.notAfter, data.pathLenConstraint, data.isEndEntity);
		} catch (AuthenticationException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorMessage(e.getMessage(), "AUTH_ERR"));
		} catch (InvalidCertificateRequestException e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage(e.getMessage(), e.getErrorCode()));
		} catch (InvalidIssuerException e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage(e.getMessage(), e.getErrorCode()));
		} catch (AccessDeniedException e) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorMessage(e.getMessage(), "FORBIDDEN_ERR"));
		}
		return new ResponseEntity<Void>(HttpStatus.OK);
	}
	
	@GetMapping
	public ResponseEntity<List<SimpleCertificateDTO>> getCertificates(){
		return ResponseEntity.ok(certService.getAllCertificates().stream().map(t -> new SimpleCertificateDTO(t)).toList());
	}
}
