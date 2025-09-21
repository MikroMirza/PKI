package rs.tim33.PKI.DTO.Verification;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VerificationResponse {
    private boolean success;
    private String message;
    private String errorCode;

    public VerificationResponse() {}

    public VerificationResponse(boolean success, String message, String errorCode) {
        this.success = success;
        this.message = message;
        this.errorCode = errorCode;
    }

}