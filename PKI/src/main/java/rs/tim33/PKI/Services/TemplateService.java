package rs.tim33.PKI.Services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.persistence.EntityNotFoundException;
import rs.tim33.PKI.DTO.Certificate.TemplateDTO;
import rs.tim33.PKI.Models.CertificateModel;
import rs.tim33.PKI.Models.CertificateTemplate;
import rs.tim33.PKI.Models.Role;
import rs.tim33.PKI.Repositories.CertTemplateRepository;
import rs.tim33.PKI.Repositories.CertificateRepository;
import rs.tim33.PKI.Utils.CertificateService;
import rs.tim33.PKI.Utils.LoggedUserUtils;

@Service
public class TemplateService {
	@Autowired
	private CertificateRepository certRepo;
	@Autowired
	private CertTemplateRepository templateRepo;
	@Autowired
	private LoggedUserUtils loggedUserUtils;
	@Autowired
	private CertificateService certService;
	
	public void createTemplate(TemplateDTO data) {
		CertificateModel cert = certRepo.findById(data.certId).orElseThrow(() -> new EntityNotFoundException("No certificate with that id found"));
		
		if(loggedUserUtils.getLoggedInRole() == Role.CA)
			if(!certService.getUsersCertificates(loggedUserUtils.getLoggedInUser()).contains(cert))
				throw new EntityNotFoundException("Certificate not found");
		
		CertificateTemplate template = new CertificateTemplate(data, cert);
		templateRepo.save(template);
	}
	
	public void deleteTemplate(Long id) {
		CertificateTemplate template = templateRepo.findById(id).orElseThrow(() -> new EntityNotFoundException("Template not found"));
		
		if(loggedUserUtils.getLoggedInRole() == Role.CA)
			if(!certService.getUsersCertificates(loggedUserUtils.getLoggedInUser()).contains(template.getTemplateOwner()))
				throw new EntityNotFoundException("Template not found");
		
		templateRepo.deleteById(id);
	}
}
