package rs.tim33.PKI.Controllers;

import java.security.cert.X509CRL;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import rs.tim33.PKI.Services.CRLService;

@RestController
@RequestMapping("/crl")
public class CRLController {

    @Autowired
    private CRLService crlService;

    @GetMapping("/{issuerCertId}")
    public ResponseEntity<byte[]> getCrl(@PathVariable Long issuerCertId) {
        try {
            X509CRL crl = crlService.generateCRL(issuerCertId);

            byte[] crlBytes = crl.getEncoded(); //DER
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.valueOf("application/pkix-crl"));
            headers.setContentLength(crlBytes.length);

            return ResponseEntity.ok().headers(headers).body(crlBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(null);
        }
    }
    
}
