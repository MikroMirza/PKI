package rs.tim33.PKI.Controllers;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import rs.tim33.PKI.DTO.Verification.VerificationResponse;
import rs.tim33.PKI.Services.VerificationService;

@RestController
@RequestMapping("/api/users/")
public class VerificationController {

    @Autowired
    private VerificationService verificationService;
    
}
