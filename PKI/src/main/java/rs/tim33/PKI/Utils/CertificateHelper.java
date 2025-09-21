package rs.tim33.PKI.Utils;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateHelper {
	public static X509Certificate getX509Certificate(byte[] certData) throws Exception {
	    CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    try (ByteArrayInputStream bais = new ByteArrayInputStream(certData)) {
	        return (X509Certificate) cf.generateCertificate(bais);
	    }
	}
}
