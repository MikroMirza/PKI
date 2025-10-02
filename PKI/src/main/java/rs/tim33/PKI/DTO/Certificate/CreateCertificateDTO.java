package rs.tim33.PKI.DTO.Certificate;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;

import rs.tim33.PKI.Models.CertificateType;

public class CreateCertificateDTO {
	//The certificate data
	public CertificateType certType;
	public Long issuerId;
	public SubjectDTO subject;
	public Long templateId = 0L;
	
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
	public Integer pathLenConstraint;
}
