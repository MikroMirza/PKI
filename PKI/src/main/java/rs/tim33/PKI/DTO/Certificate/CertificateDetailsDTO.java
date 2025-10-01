package rs.tim33.PKI.DTO.Certificate;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import rs.tim33.PKI.Models.CertificateModel;

public class CertificateDetailsDTO {
	public List<StringPair> details = new ArrayList<StringPair>();
	public List<StringPair> subjectPublicKeyInfo = new ArrayList<StringPair>();
	public List<StringPair> validity = new ArrayList<StringPair>();
	public List<StringPair> extensions = new ArrayList<StringPair>();
	
	public CertificateDetailsDTO(CertificateModel certModel) {
		try {
			X509Certificate cert = certModel.getCertificate();
			details.add(new StringPair("Serial Number", cert.getSerialNumber().toString(16)));
			details.add(new StringPair("Subject", cert.getSubjectX500Principal().getName()));
			details.add(new StringPair("Issuer", cert.getIssuerX500Principal().getName()));

			details.add(new StringPair("Certificate Signature Algorithm", cert.getSigAlgName()));
			details.add(new StringPair("Certificate Signature Algorithm", Base64.getEncoder().encodeToString(cert.getSignature())));
			
			subjectPublicKeyInfo.add(new StringPair("Public Key Algorithm", cert.getPublicKey().getAlgorithm()));
			subjectPublicKeyInfo.add(new StringPair("Public Key", Base64.getEncoder().encodeToString(cert.getPublicKey().getEncoded())));

			validity.add(new StringPair("Not Before", cert.getNotBefore().toGMTString()));
			validity.add(new StringPair("Not After", cert.getNotAfter().toGMTString()));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
