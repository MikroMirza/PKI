package rs.tim33.PKI.Exceptions;
import lombok.Getter;

@Getter
public class LoginException extends RuntimeException{
	private static final long serialVersionUID=1L;
	private final String errorCode;
	
	public LoginException(String message,String errorCode){
		super(message);
		this.errorCode=errorCode;
	}
	public LoginException(String message){
		super(message);
		this.errorCode="ERR_LOGIN";
	}
}
