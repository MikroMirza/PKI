package rs.tim33.PKI.DTO.Certificate;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;

public class CreateIntermediateDTO {
	//The certificate
	public Long issuerId;
	public String cn;
	public String organization;
	public String organizationUnit;
	public LocalDateTime notBefore;
	public LocalDateTime notAfter;
	public Integer pathLenConstraint;
}
