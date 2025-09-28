package rs.tim33.PKI.DTO.User;

import java.util.List;

import rs.tim33.PKI.DTO.Certificate.SimpleCertificateDTO;
import rs.tim33.PKI.Models.UserModel;

public class SimpleUserDTO {
	public Long id;
	public String email;
	public List<SimpleCertificateDTO> certs;
	
	public SimpleUserDTO(UserModel user) {
		this.id = user.getId();
		this.email = user.getEmail();
		this.certs = user.getCertificates().stream().map(c -> new SimpleCertificateDTO(c)).toList();
	}
}
