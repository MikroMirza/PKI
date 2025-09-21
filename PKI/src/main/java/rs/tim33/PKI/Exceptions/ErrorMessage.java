package rs.tim33.PKI.Exceptions;

public class ErrorMessage {
    private String message;
    private String errorCode;

    public ErrorMessage(String message, String errorCode) {
        this.message = message;
        this.errorCode = errorCode;
    }

    public String getMessage() {
        return message;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
