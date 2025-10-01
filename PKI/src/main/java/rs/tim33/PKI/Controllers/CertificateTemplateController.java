package rs.tim33.PKI.Controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import rs.tim33.PKI.DTO.Certificate.TemplateDTO;

@RestController
@RequestMapping("/api/certificates/templates")
public class CertificateTemplateController {
	
	@GetMapping("/{id}")
	ResponseEntity<?> getTemplate(@PathVariable Long id) {
		return ResponseEntity.status(HttpStatus.OK).body(null);
	}
	
	@PostMapping
	ResponseEntity<?> createTemplate(@RequestBody TemplateDTO data){
		return ResponseEntity.status(HttpStatus.OK).body(null);
	}
	
	@DeleteMapping("/{id}")
	ResponseEntity<?> deleteTemplate(@PathVariable Long id){
		return ResponseEntity.status(HttpStatus.OK).body(null);
	}
}
