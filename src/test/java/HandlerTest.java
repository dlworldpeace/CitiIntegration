package test.java;

import static main.java.Handler.convertDocToString;
import static main.java.Handler.convertStringToDoc;
import static main.java.Handler.decryptEncryptedAndSignedXML;
import static main.java.Handler.encryptSignedXMLPayloadDoc;
import static main.java.Handler.parseAuthOrPayInitResponse;
import static main.java.Handler.signXMLPayloadDoc;
import static main.java.Handler.verifyDecryptedXML;
import static main.java.HandlerConstant.authType;
import static main.java.HandlerConstant.tagName_Auth;
import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.xml.xpath.XPathExpressionException;
import main.java.Handler;
import main.java.HandlerException;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.w3c.dom.Document;

@RunWith(JUnit4.class)
public class HandlerTest {

  private final static String EMPTY_STRING = "";
  private final static String SPACE_STRING = " ";
  private final static String SOME_XML = "<hi>123</hi>";

  private Handler handler;

  /**
   * Sets up the test fixture.
   * (Called before every test case method.)
   */
  @Before
  public void setUp() throws HandlerException {
    handler = new Handler();
    handler.loadKeystore();
  }

  /**
   * Tears down the test fixture.
   * (Called after every test case method.)
   */
  @After
  public void tearDown() {
    handler = null;
  }

  @Test
  public void convertStringToDocToString_xmlStr_remainsSame ()
      throws HandlerException, IOException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));
    final String strWithoutFirstLine = str.substring(str.indexOf('\n')+1);

    assertEquals(strWithoutFirstLine,
        convertDocToString(convertStringToDoc(strWithoutFirstLine)));
  }

  @Test
  public void convertStringToDoc_improperXmlStr_success()
      throws HandlerException {
    convertStringToDoc(SOME_XML);
  }

  @Test (expected = HandlerException.class)
  public void convertStringToDoc_emptyStr_throwsHandlerException ()
      throws HandlerException {
    convertStringToDoc(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void convertStringToDoc_nonXmlStr_throwsHandlerException ()
      throws HandlerException {
    convertStringToDoc(SPACE_STRING);
  }

  @Test
  public void signXMLPayloadDoc_verifyDecryptedXML_success ()
      throws IOException, HandlerException, XMLSecurityException,
      CertificateEncodingException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate signingCert = handler.getClientSigningCert();
    PrivateKey privKey = handler.getClientPrivateKey();
    Document doc = convertStringToDoc(str);
    signXMLPayloadDoc(doc, signingCert, privKey);
    verifyDecryptedXML(doc, signingCert);
  }

  @Test (expected = HandlerException.class)
  public void signXMLPayloadDoc_wrongPairOfCertAndPrivKey_throwsHandlerException ()
      throws IOException, HandlerException, XMLSecurityException,
      CertificateEncodingException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate signingCert = Handler.getCitiSigningCert();
    PrivateKey privKey = handler.getClientPrivateKey();
    Document doc = convertStringToDoc(str);
    signXMLPayloadDoc(doc, signingCert, privKey);
    verifyDecryptedXML(doc, signingCert);
  }

  @Test
  public void signXMLPayloadDoc_alreadySignedDoc_throwsHandlerException ()
      throws IOException, HandlerException, XMLSecurityException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate signingCert = Handler.getCitiSigningCert();
    PrivateKey privKey = handler.getClientPrivateKey();
    Document doc = convertStringToDoc(str);
    signXMLPayloadDoc(doc, signingCert, privKey);
    String payloadSignedOnce = convertDocToString(doc);
    signXMLPayloadDoc(doc, signingCert, privKey);
    String payloadSignedTwice = convertDocToString(doc);
    assertEquals(payloadSignedOnce, payloadSignedTwice);
  }

  @Test (expected = HandlerException.class)
  public void decryptEncryptedAndSignedXML_nonEncryptedXml_throwsHandlerException ()
      throws HandlerException, XMLEncryptionException, IOException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));

    PrivateKey privKey = handler.getClientPrivateKey();
    Document nonEncryptedDoc = convertStringToDoc(str);
    decryptEncryptedAndSignedXML(nonEncryptedDoc, privKey);
  }

  @Test
  public void decryptEncryptedAndSignedXML_encryptSignedXMLPayloadDoc_remainsSame ()
      throws IOException, HandlerException, XMLEncryptionException {

    org.apache.xml.security.Init.init();

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));

    PublicKey pubKey = handler.getClientSigningCert().getPublicKey();
    PrivateKey privKey = handler.getClientPrivateKey();
    Document encryptedDoc = encryptSignedXMLPayloadDoc(
        convertStringToDoc(str), pubKey);
    String decryptedStr = convertDocToString(
        decryptEncryptedAndSignedXML(encryptedDoc, privKey));
    assertEquals(str, decryptedStr);
  }



  @Test
  public void authenticate_responseReceivedSuccess ()
      throws IOException, XMLSecurityException, HandlerException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/OutgoingPayment/"
            + "XML Request/AuthorizationRequest_V2_Plain.txt")));

    String response = handler.authenticate(str);
  }

  @Test
  public void parseAuthOrPayInitResponse_successResponse_parseSuccess ()
      throws HandlerException, XPathExpressionException, IOException {

    final String response = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/"
            + "XML Response/AuthorizationResponse_Signed.txt")));
    final String oAuthToken = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/"
            + "XML Response/AuthorizationResponse_Token.txt")));

    String oAuthTokenParsed = parseAuthOrPayInitResponse(
        convertStringToDoc(response), authType, tagName_Auth);
    assertEquals(oAuthTokenParsed, oAuthToken);
  }

  @Test
  public void authentication_validateAPIs_success ()
      throws IOException, XMLSecurityException, HandlerException,
      CertificateEncodingException, XPathExpressionException {

    final String strAuth = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/XML Request/"
            + "AuthorizationRequest_V3_Plain.txt")));
    String response = handler.authenticate(strAuth);
    String decryptedVerifiedResponse = handler.decryptAndVerifyXML(response);
    String oAuthToken = parseAuthOrPayInitResponse(
        convertStringToDoc(decryptedVerifiedResponse), authType, tagName_Auth);
    handler.setOAuthToken(oAuthToken);

//    final String strStatRet = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/StatementRetrieval/"
//            + "XML Request/StatementRetrievalRequest_Plain.txt")));
//    String resStatRet = new String(handler.retrieveStatement(strStatRet));
//    System.out.println(resStatRet);

//    InputStream is = handler.requestForStatement(strStatRet);
//    String resStatRet_Encrypted = IOUtils.toString(is, "UTF-8");
//    String resStatRet = handler.decryptAndVerifyXML(resStatRet_Encrypted);
//    System.out.println(resStatRet);

    final String strBalance = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/"
            + "XML Request/BalanceInquiryRequest_Plain_Real.txt")));
    String resBalance = handler.checkBalance(strBalance);
    System.out.println(resBalance);
  }

//
//  @Test
//  public void decryptEncryptedAndSignedXML() {
//  }
//
//  @Test
//  public void getCitiSigningCert() {
//  }
//
//  @Test
//  public void verifyDecryptedXML() {
//  }
//
//  @Test
//  public void decryptAndVerifyXML() {
//  }
//
//  @Test
//  public void parseAuthOrPayInitResponse() {
//  }
//
//  @Test
//  public void authenticate() {
//  }
//
//  @Test
//  public void generateBase64InputFromISOXMLPayload() {
//  }
//
//  @Test
//  public void initPayment() {
//  }
//
//  @Test
//  public void checkBalance() {
//  }
//
//  @Test
//  public void requestForStatement() {
//  }
//
//  @Test
//  public void handleHttp() {
//  }
//
//  @Test
//  public void retrieveStatement() {
//  }
}