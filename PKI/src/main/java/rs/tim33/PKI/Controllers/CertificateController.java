package rs.tim33.PKI.Controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import rs.tim33.PKI.DTO.Certificate.CreateIntermediateDTO;
import rs.tim33.PKI.DTO.Certificate.SimpleCertificateDTO;
import rs.tim33.PKI.Utils.CertificateService;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {
	@Autowired
	private CertificateService certService;
	
	@PostMapping("/intermediate")
	public ResponseEntity<Void> createIntermediate(@RequestBody CreateIntermediateDTO data){
		try {
			certService.createIntermediate(data.issuerId, data.organization, data.organizationUnit, data.daysValid);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new ResponseEntity<Void>(HttpStatus.OK);
	}
	
	@GetMapping
	public ResponseEntity<List<SimpleCertificateDTO>> getCertificates(){
		return ResponseEntity.ok(certService.getAllCertificates().stream().map(t -> new SimpleCertificateDTO(t)).toList());
	}
}
