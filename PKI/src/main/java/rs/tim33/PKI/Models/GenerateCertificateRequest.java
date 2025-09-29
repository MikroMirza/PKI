package rs.tim33.PKI.Models;

import java.time.LocalDateTime;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import rs.tim33.PKI.Utils.RequestStatus;

@Entity
@Getter
@Setter
public class GenerateCertificateRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String commonName;
    private String organization;
    private String organizationalUnit;
    private String country;
    private String email;

    private LocalDateTime notBefore;
    private LocalDateTime notAfter;

    private Long issuerCertId;

    @Enumerated(EnumType.STRING)
    private RequestStatus status = RequestStatus.PENDING;

    private Integer pathLenConstraint;

    private boolean endEntity;

    public String toSubjectDn() {
        return "CN=" + commonName + ", O=" + organization +
               ", OU=" + organizationalUnit +
               ", C=" + country + ", E=" + email;
    }
}
