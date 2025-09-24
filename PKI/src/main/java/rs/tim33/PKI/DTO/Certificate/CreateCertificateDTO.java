package rs.tim33.PKI.DTO.Certificate;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;

public class CreateCertificateDTO {
	//The certificate data
	public Long issuerId;
	public SubjectDTO subject;
	public LocalDateTime notBefore;
	public LocalDateTime notAfter;
	
	//EXTENSIONS
	//SAN
	public List<TypeValue> san;
	
	//KeyUsage
	public List<String> keyUsage;
	
	//ExtendedKeyUsage
	public List<String> extendedKeyUsage;
	
	//BasicConstraints
	public Boolean isEndEntity;
	public Integer pathLenConstraint;
}
