package rs.tim33.PKI.Controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.persistence.EntityNotFoundException;
import rs.tim33.PKI.DTO.Certificate.TemplateDTO;
import rs.tim33.PKI.Models.CertificateTemplate;
import rs.tim33.PKI.Repositories.CertTemplateRepository;
import rs.tim33.PKI.Services.TemplateService;

@RestController
@RequestMapping("/api/certificates/templates")
public class CertificateTemplateController {
	@Autowired
	private CertTemplateRepository tempRepo;
	@Autowired
	private TemplateService tempService;
	
	
	@GetMapping("/{id}")
	ResponseEntity<?> getTemplate(@PathVariable Long id) {
		CertificateTemplate temp = this.tempRepo.findById(id).orElse(null);
		if (temp != null)
			return ResponseEntity.status(HttpStatus.OK).body(new TemplateDTO(temp));
		return ResponseEntity.notFound().build();
	}
	
	@PostMapping
	ResponseEntity<?> createTemplate(@RequestBody TemplateDTO data){
		try {
			this.tempService.createTemplate(data);
		} catch (EntityNotFoundException e) {
			return ResponseEntity.notFound().build();
		}
		return ResponseEntity.status(HttpStatus.OK).body(null);
	}
	
	@DeleteMapping("/{id}")
	ResponseEntity<?> deleteTemplate(@PathVariable Long id){
		try {
			this.tempService.deleteTemplate(id);
		} catch (EntityNotFoundException e) {
			return ResponseEntity.notFound().build();
		}
		return ResponseEntity.status(HttpStatus.OK).body(null);
	}
}
