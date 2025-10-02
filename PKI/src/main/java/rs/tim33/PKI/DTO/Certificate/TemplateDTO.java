package rs.tim33.PKI.DTO.Certificate;

import java.util.ArrayList;
import java.util.List;

import rs.tim33.PKI.Models.CertificateTemplate;

public class TemplateDTO {
	public Long id;
	
	public String templateName;
	public Long certId;
	
	//Empty or null values are ignored
	public String cnRegex;
	
	//SAN
	//What SAN types are available
	public List<String> allowedTypes;
	//The regex for each SAN type
	//If empty or null, anything is allowed
	public String dnsRegex;
	public String ipRegex;
	public String uriRegex;
	public String emailRegex;
	
	//Key usage
	public List<String> keyUsages;
	
	//Extended key usage
	public List<String> extKeyUsages;
	
	//TTL in days
	//if 0 ignore it
	public Integer ttl;
	
	public TemplateDTO() {}
	
	public TemplateDTO(CertificateTemplate template) {
		this.id = template.getId();
		this.templateName = template.getName();
		this.certId = template.getTemplateOwner().getId();
		this.cnRegex = template.getCnRegex();
		this.allowedTypes = new ArrayList<String>(template.getAllowedTypes());
		this.dnsRegex = template.getDnsRegex();
		this.ipRegex = template.getIpRegex();
		this.uriRegex = template.getUriRegex();
		this.emailRegex = template.getEmailRegex();
		this.keyUsages = new ArrayList<String>(template.getKeyUsages());
		this.extKeyUsages = new ArrayList<String>(template.getExtKeyUsages());
		this.ttl = template.getTtl();
	}
}
