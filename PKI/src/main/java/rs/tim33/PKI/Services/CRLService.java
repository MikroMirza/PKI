package rs.tim33.PKI.Services;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.util.Date;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.math.BigInteger;

import rs.tim33.PKI.Models.CertificateModel;
import rs.tim33.PKI.Repositories.CertificateRepository;
import rs.tim33.PKI.Utils.CertificateService;

import org.bouncycastle.asn1.x509.CRLReason;

import java.time.ZoneId;

@Service
public class CRLService {
    @Autowired
    private CertificateRepository certRepo;
    @Autowired
    private CertificateService certificateService;

    public X509CRL generateCRL(Long issuerCertId) throws Exception {
        CertificateModel issuerCert = certRepo.findById(issuerCertId)
            .orElseThrow(() -> new IllegalArgumentException("Issuer not found"));

        PrivateKey issuerKey = certificateService.getPrivateKeyOfCert(issuerCertId);

        X500Principal issuerX500 = new X500Principal(issuerCert.getSubjectDn());
        Date now = new Date();
        Date nextUpdate = new Date(now.getTime() + 7L * 24 * 3600 * 1000);

        JcaX509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(issuerX500, now);
        crlBuilder.setNextUpdate(nextUpdate);

        for (CertificateModel revoked : certRepo.findByIssuerAndRevokedTrue(issuerCert)) {
        	crlBuilder.addCRLEntry(
        		    new BigInteger(revoked.getSerialNumber()),
        		    Date.from(revoked.getRevokedAt().atZone(ZoneId.systemDefault()).toInstant()),
        		    1
        		    //Maybe change 1 to 0 or something else if the reason of revokation isn't specified.
        		);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        X509CRLHolder crlHolder = crlBuilder.build(signer);

        return new JcaX509CRLConverter().getCRL(crlHolder);
    }
}
