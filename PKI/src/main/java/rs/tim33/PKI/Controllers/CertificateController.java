package rs.tim33.PKI.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import rs.tim33.PKI.DTO.Certificate.CreateIntermediateDTO;
import rs.tim33.PKI.Utils.CertificateService;

@RestController
@RequestMapping("/api/certificates")
public class CertificateController {
	@Autowired
	private CertificateService certService;
	
	@PostMapping("/self-signed")
	public ResponseEntity<Void> createSelfSigned(){
		return new ResponseEntity<Void>(HttpStatus.OK);
	};
	
	@PostMapping("/intermediate")
	public ResponseEntity<Void> createIntermediate(@RequestBody CreateIntermediateDTO data){
		try {
			certService.createIntermediate(data.issuerId, data.organizationUnit, data.daysValid);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return new ResponseEntity<Void>(HttpStatus.OK);
	}
}
