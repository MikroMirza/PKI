package rs.tim33.PKI.Utils;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class ApplicationStartup {
	@Autowired
	private CertificateService certService;
	
	
	@EventListener(ApplicationReadyEvent.class)
	public void onAppReady() {
		try {
			certService.createSelfSigned("CN=Root, O=Smekeri", 180);
		} catch (CertificateException | CertIOException | OperatorCreationException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
}
