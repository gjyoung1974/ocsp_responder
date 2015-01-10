package com.goyoung.pki.util.ocsp;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;


/**
 * Servlet implementation class CocspServlet
 */
@WebServlet("/ocsp.exe")
public class CocspServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public CocspServlet() {
        super();
        // TODO Auto-generated constructor stub
    }
     
   // An HTTP-based OCSP response is composed of the appropriate HTTP
   // headers, followed by the binary value of the DER encoding of the
   // OCSPResponse.  The Content-Type header has the value
   // "application/ocsp-response".  The Content-Length header SHOULD
   // specify the length of the response.  Other HTTP headers MAY be
   //  present and MAY be ignored if not understood by the requestor.

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
			
		OCSPReq ocspRequest = null;

		PrivateKey responderKey = null;
		PublicKey pubKey = null;
		CertificateID revokedID = null;
		try {
			CGenOCSPResponse.generateOCSPResponse(ocspRequest, responderKey, pubKey, revokedID);
		} catch (NoSuchProviderException | OCSPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
			//final String CommonName = request.getParameter("CN");
			//final String ECID = request.getParameter("ECID");
			//final String OU = request.getParameter("OU");
			//final String challenge = request.getParameter("challenge");
					
			response.setContentType("application/ocsp-response");
			
		      ServletOutputStream stream = null;
		      String test = "sdfasdf";
		     stream = response.getOutputStream();
		      
		       //set response headers
		     //response.setCharacterEncoding("utf-8");
		     //response.setContentType("application/x-apple-aspen-config");
		       
		       //response.addHeader("Content-Disposition","attachment; filename=ACMEPKI.mobileconfig" );
		       //response.setContentLength( (int) test.length() );
		      
		      
				stream.write(test.getBytes());
				
		}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		//final String CommonName = request.getParameter("CN");
		//final String ECID = request.getParameter("ECID");
		//final String OU = request.getParameter("OU");
		//final String challenge = request.getParameter("challenge");
		
				
		response.setContentType("application/ocsp-response");
		
	      ServletOutputStream stream = null;
	      String test = "sdfasdf";
	     stream = response.getOutputStream();
	      
	       //set response headers
	     //response.setCharacterEncoding("utf-8");
	     //response.setContentType("application/x-apple-aspen-config");
	       
	       //response.addHeader("Content-Disposition","attachment; filename=ACMEPKI.mobileconfig" );
	       //response.setContentLength( (int) test.length() );
	      
	      
			stream.write(test.getBytes());
	}

}
