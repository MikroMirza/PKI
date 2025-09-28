package rs.tim33.PKI.DTO.Certificate;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RevokedCertificateDTO {
	private Long certId;
	private Integer reason;
}
