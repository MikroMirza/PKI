package rs.tim33.PKI.DTO.Certificate;

import java.time.LocalDateTime;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GenerateCertificateRequestDTO {
    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;

    private LocalDateTime notBefore;
    private LocalDateTime notAfter;

    private Long issuerCertId;
}
