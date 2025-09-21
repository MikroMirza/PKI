package rs.tim33.PKI.Exceptions;

import lombok.Getter;

@Getter
public class VerificationTokenException extends RuntimeException {
	private static final long serialVersionUID = 1L;
	
	private final String errorCode;
	
	public VerificationTokenException(String message, String errorCode) {
		super(message);
		this.errorCode = errorCode;
	}
	
	public VerificationTokenException(String message) {
		super(message);
		this.errorCode = "";
	}
}
