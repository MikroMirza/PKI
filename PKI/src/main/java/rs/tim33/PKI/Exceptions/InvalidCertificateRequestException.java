package rs.tim33.PKI.Exceptions;

import lombok.Getter;

@Getter
public class InvalidCertificateRequestException extends RuntimeException{
	private static final long serialVersionUID=1L;
	private final String errorCode;
	
	public InvalidCertificateRequestException(String message,String errorCode){
		super(message);
		this.errorCode=errorCode;
	}
	public InvalidCertificateRequestException(String message){
		super(message);
		this.errorCode="ERR_CERT_REQUEST";
	}
}
