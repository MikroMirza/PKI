package rs.tim33.PKI.Controllers;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.AuthenticationException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import rs.tim33.PKI.DTO.Certificate.CreateCertificateDTO;
import rs.tim33.PKI.DTO.Certificate.GenerateCertificateRequestDTO;
import rs.tim33.PKI.DTO.Certificate.RevokedCertificateDTO;
import rs.tim33.PKI.DTO.Certificate.SimpleCertificateDTO;
import rs.tim33.PKI.Exceptions.CertificateGenerationException;
import rs.tim33.PKI.Exceptions.ErrorMessage;
import rs.tim33.PKI.Exceptions.InvalidCertificateRequestException;
import rs.tim33.PKI.Exceptions.InvalidIssuerException;
import rs.tim33.PKI.Models.CertificateModel;
import rs.tim33.PKI.Models.CertificateType;
import rs.tim33.PKI.Repositories.CertificateRepository;
import rs.tim33.PKI.Services.KeystoreService;
import rs.tim33.PKI.Utils.CertificateService;
import rs.tim33.PKI.Utils.CertificateService.KeyPairAndCert;
import rs.tim33.PKI.Utils.KeyHelper;
import rs.tim33.PKI.Utils.RevocationReason;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {
	@Autowired
	private CertificateService certService;
	@Autowired
	private CertificateRepository certRepo;
	@Autowired
	private KeystoreService keystoreService;
	@Autowired
	private KeyHelper keyHelper;
	
	@PostMapping
	public ResponseEntity<?> create(@RequestBody CreateCertificateDTO data){
		try {
			certService.generateCertificate(data);
		} catch (AuthenticationException e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorMessage(e.getMessage(), "AUTH_ERR"));
		} catch (InvalidCertificateRequestException e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage(e.getMessage(), e.getErrorCode()));
		} catch (InvalidIssuerException e) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage(e.getMessage(), e.getErrorCode()));
		} catch (AccessDeniedException e) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(new ErrorMessage(e.getMessage(), "FORBIDDEN_ERR"));
		} catch (CertificateGenerationException e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ErrorMessage(e.getMessage(), "GEN_ERR"));
		}
		return new ResponseEntity<Void>(HttpStatus.OK);
	}
	
	@PostMapping("/revoked")
    public ResponseEntity<?> revokeCertificate(@RequestBody RevokedCertificateDTO certDTO){
    	Optional<CertificateModel> optCert = certRepo.findById(certDTO.getCertId());
		if(optCert.isEmpty()) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage("You must select a certificate to revoke first", "NO_CERT_SELECTED"));
		}
		CertificateModel cert = optCert.get();
		RevocationReason reason = RevocationReason.fromCode(certDTO.getReason());
		certService.revokeCertificate(cert, reason);
		return ResponseEntity.ok().build();
    }
	
	@PostMapping("/rerevoked")
    public ResponseEntity<?> rerevokeCertificate(@RequestBody RevokedCertificateDTO certDTO){
    	Optional<CertificateModel> optCert = certRepo.findById(certDTO.getCertId());
		if(optCert.isEmpty()) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage("You must select a certificate to unrevoke first", "NO_CERT_SELECTED"));
		}
		CertificateModel cert = optCert.get();
		RevocationReason reason = RevocationReason.fromCode(certDTO.getReason());
		if(reason.getCode()!=6) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessage("This certificate can be unrevoked", "INCORRECT_REASONING"));
		}
		certService.rerevokeCertificate(cert, reason);
		return ResponseEntity.ok().build();
    }
	
	@PostMapping("/{id}/download")
	public ResponseEntity<byte[]> downloadCertificate(@PathVariable Long id,@RequestBody String password) throws Exception {

	    CertificateModel certModel = certRepo.findById(id)
	            .orElseThrow(() -> new RuntimeException("Certificate not found"));

	    X509Certificate x509Cert = certModel.getCertificate();
	    PrivateKey privateKey;
		try {
			privateKey = certService.getPrivateKeyOfCert(id);
		} catch (Exception e) {
			e.printStackTrace();
		    throw new RuntimeException("Failed to decrypt private key", e);
		}
	    String alias = certModel.getAlias();

	    byte[] keystoreBytes = keystoreService.exportAsPKCS12(privateKey, x509Cert, alias, password);

	    return ResponseEntity.ok()
	            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"certificate.p12\"")
	            .contentType(MediaType.APPLICATION_OCTET_STREAM)
	            .body(keystoreBytes);
	}


	@PostMapping("/generate")
	public ResponseEntity<?> generateCertificate(@RequestBody GenerateCertificateRequestDTO dto) {
	    try {
	        CertificateModel cert = certService.generateCertificateFromRequest(dto);
	        return ResponseEntity.ok(cert);
	    } catch (AuthenticationException e) {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
	                             .body(new ErrorMessage(e.getMessage(), "AUTH_ERR"));
	    } catch (AccessDeniedException e) {
	        return ResponseEntity.status(HttpStatus.FORBIDDEN)
	                             .body(new ErrorMessage(e.getMessage(), "FORBIDDEN_ERR"));
	    } catch (CertificateGenerationException e) {
	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                             .body(new ErrorMessage(e.getMessage(), "GEN_ERR"));
	    }
	}

	
	@GetMapping
	public ResponseEntity<List<SimpleCertificateDTO>> getCertificates(){
		return ResponseEntity.ok(certService.getAllCertificates().stream().map(t -> new SimpleCertificateDTO(t)).toList());
	}
	
	@GetMapping("/available")
	public ResponseEntity<List<SimpleCertificateDTO>> getAvailableCertificates(){
		return ResponseEntity.ok(certService.getAvailableCertificates().stream().map(t -> new SimpleCertificateDTO(t)).toList());
	}
	
	@GetMapping("/availableCA")
	public ResponseEntity<List<SimpleCertificateDTO>> getAvailableCACertificates(){
		return ResponseEntity.ok(certService.getAvailableCACertificates().stream().map(t -> new SimpleCertificateDTO(t)).toList());
	}
}
