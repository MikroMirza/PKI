package rs.tim33.PKI.Exceptions;

import lombok.Getter;

@Getter
public class InvalidIssuerException extends RuntimeException{
	private static final long serialVersionUID=1L;
	private final String errorCode;
	
	public InvalidIssuerException(String message,String errorCode){
		super(message);
		this.errorCode=errorCode;
	}
	public InvalidIssuerException(String message){
		super(message);
		this.errorCode="ERR_INVALID_ISSUER";
	}
}
