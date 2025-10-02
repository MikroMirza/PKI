package rs.tim33.PKI.DTO.Certificate;
import java.time.LocalDate;

public class CsrRequestDTO {
    private String csrPem;
    private Long issuerId;
    private LocalDate notBefore;
    private LocalDate notAfter;

    public String getCsrPem() { return csrPem; }
    public void setCsrPem(String csrPem) { this.csrPem = csrPem; }

    public Long getIssuerId() { return issuerId; }
    public void setIssuerId(Long issuerId) { this.issuerId = issuerId; }

    public LocalDate getNotBefore() { return notBefore; }
    public void setNotBefore(LocalDate notBefore) { this.notBefore = notBefore; }

    public LocalDate getNotAfter() { return notAfter; }
    public void setNotAfter(LocalDate notAfter) { this.notAfter = notAfter; }
}

