package rs.tim33.PKI.Exceptions;
import lombok.Getter;

@Getter
public class ValidateArgumentsException extends RuntimeException {
	private static final long serialVersionUID = 1L;
	private final String errorCode;

	public ValidateArgumentsException(String message, String error) {
		super(message);
		this.errorCode = error;
	}
	
	public ValidateArgumentsException(String message) {
		super(message);
		this.errorCode = "ERR_VALIDATION";
	}
}
