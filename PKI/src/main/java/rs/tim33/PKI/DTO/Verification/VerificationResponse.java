package rs.tim33.PKI.DTO.Verification;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VerificationResponse {
	private String message;
	
	public VerificationResponse(String message) {
		this.message = message;	
	}
}
