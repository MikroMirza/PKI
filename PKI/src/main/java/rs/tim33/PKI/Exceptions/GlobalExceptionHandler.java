package rs.tim33.PKI.Exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;


@ControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(VerificationTokenException.class)
    public ResponseEntity<ErrorMessage> handleException(VerificationTokenException ex) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ErrorMessage(ex.getMessage(), ex.getErrorCode()));
    }
    
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorMessage> handleInvalidJson(HttpMessageNotReadableException ex) {
        return ResponseEntity
                .badRequest()
                .body(new ErrorMessage(ex.getMessage(), "MSG_NOT_READABLE"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorMessage> handleValidationErrors(MethodArgumentNotValidException ex) {
        return ResponseEntity
                .badRequest()
                .body(new ErrorMessage(ex.getMessage(), "ARG_INVALID"));
    }
}

