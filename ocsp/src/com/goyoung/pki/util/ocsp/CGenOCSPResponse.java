package com.goyoung.pki.util.ocsp;

import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.util.Date;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.BasicOCSPRespGenerator;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.CertificateStatus;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.OCSPRespGenerator;
import org.bouncycastle.ocsp.Req;
import org.bouncycastle.ocsp.RevokedStatus;

public class CGenOCSPResponse {

	// KeyPair rootPair=null;// = Utils.generateRSAKeyPair();
	// KeyPair interPair =null;// Utils.generateRSAKeyPair();
	//
	// X509Certificate rootCert=null;// = Utils.generateRootCert(rootPair);
	// X509Certificate interCert=null;// =
	// Utils.generateIntermediateCert(interPair.getPublic(),
	// rootPair.getPrivate(), rootCert);

	public static OCSPResp generateOCSPResponse(OCSPReq request,
			PrivateKey responderKey, PublicKey pubKey, CertificateID revokedID)
			throws NoSuchProviderException, OCSPException {
		BasicOCSPRespGenerator basicRespGen = new BasicOCSPRespGenerator(pubKey);

		X509Extensions reqExtensions = request.getRequestExtensions();

		if (reqExtensions != null) {
			X509Extension ext = reqExtensions
					.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);

			if (ext != null) {
				Vector<ASN1ObjectIdentifier> oids = new Vector<ASN1ObjectIdentifier>();
				Vector<X509Extension> values = new Vector<X509Extension>();

				oids.add(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
				values.add(ext);

				basicRespGen.setResponseExtensions(new X509Extensions(oids,
						values));
			}
		}

		Req[] requests = request.getRequestList();

		for (int i = 0; i != requests.length; i++) {
			CertificateID certID = requests[i].getCertID();

			// this would normally be a lot more general!
			if (certID.equals(revokedID)) {
				basicRespGen.addResponse(certID, new RevokedStatus(new Date(),
						CRLReason.privilegeWithdrawn));
			} else {
				basicRespGen.addResponse(certID, CertificateStatus.GOOD);
			}
		}

		BasicOCSPResp basicResp = basicRespGen.generate("SHA256WithRSA",
				responderKey, null, new Date(), "BC");

		OCSPRespGenerator respGen = new OCSPRespGenerator();

		return respGen.generate(OCSPRespGenerator.SUCCESSFUL, basicResp);
	}
}