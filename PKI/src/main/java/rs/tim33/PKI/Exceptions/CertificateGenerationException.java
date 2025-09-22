package rs.tim33.PKI.Exceptions;

public class CertificateGenerationException extends RuntimeException{
	private static final long serialVersionUID=1L;
	private final String errorCode;
	
	public CertificateGenerationException(String message,String errorCode){
		super(message);
		this.errorCode=errorCode;
	}
	public CertificateGenerationException(String message){
		super(message);
		this.errorCode="ERR_CERT_GEN";
	}
}
