package rs.tim33.PKI.Models;

import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.Setter;
import rs.tim33.PKI.DTO.Certificate.TemplateDTO;

@Entity
@Getter
@Setter
public class CertificateTemplate {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	private String name;
	
	@ManyToOne
	private CertificateModel templateOwner;
	
	private String cnRegex;
	
	//SAN
	
	//What SAN types are available
	private List<String> allowedTypes;
	//The regex for each SAN type
	//If empty or null, anything is allowed
	private String dnsRegex;
	private String ipRegex;
	private String uriRegex;
	private String emailRegex;
	
	//Key usage
	private List<String> keyUsages;
	
	//Extended key usage
	private List<String> extKeyUsages;
	
	//TTL in days
	//if 0 ignore it
	private Integer ttl;
	
	public CertificateTemplate() {}
	
	public CertificateTemplate(TemplateDTO data, CertificateModel owner) {
		this.name = data.templateName;
		this.templateOwner = owner;
		this.cnRegex = data.cnRegex;
		this.allowedTypes = new ArrayList<String>(data.allowedTypes);
		this.dnsRegex = data.dnsRegex;
		this.ipRegex = data.ipRegex;
		this.uriRegex = data.uriRegex;
		this.emailRegex = data.emailRegex;
		this.keyUsages = new ArrayList<String>(data.keyUsages);
		this.extKeyUsages = new ArrayList<String>(data.extKeyUsages);
		this.ttl = data.ttl;
	}
}
