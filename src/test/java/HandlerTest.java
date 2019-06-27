package test.java;

import static main.java.Handler.convertDocToXMLStr;
import static main.java.Handler.convertXMLStrToDoc;
import static main.java.Handler.des3DecodeCBC;
import static main.java.Handler.extractAttachmentDecryptionKey;
import static main.java.Handler.extractStatementId;
import static main.java.Handler.decryptEncryptedAndSignedXML;
import static main.java.Handler.encryptSignedXMLPayloadDoc;
import static main.java.Handler.generateBase64PayloadFromISOXML;
import static main.java.Handler.getCitiSigningCert;
import static main.java.Handler.parseAuthOrPayInitResponse;
import static main.java.Handler.parseMIMEResponse;
import static main.java.Handler.signXMLPayloadDoc;
import static main.java.Handler.verifyDecryptedXML;
import static main.java.Constant.KEYSTORE_ALIAS;
import static main.java.Constant.KEYSTORE_FILEPATH;
import static main.java.Constant.KEYSTORE_PASSWORD;
import static main.java.Constant.TYPE_AUTH;
import static main.java.Constant.TYPE_PAY_INIT;
import static main.java.Constant.TAG_NAME_AUTH;
import static main.java.Constant.TAG_NAME_PAY_INIT;
import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import javax.xml.xpath.XPathExpressionException;
import main.java.Handler;
import main.java.HandlerException;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.w3c.dom.Document;

@RunWith(JUnit4.class)
public class HandlerTest {

  private final static String EMPTY_STRING = "";
  private final static String WHITE_SPACE = " ";
  private final static String SOME_XML = "<hi>123</hi>";

  private Handler handler;

  @Rule
  public ExpectedException exception = ExpectedException.none();

  /**
   * Sets up the test fixture.
   * (Called before every test case method.)
   */
  @Before
  public void setUp() throws HandlerException {
    if(handler == null) {
      handler = new Handler();
      handler.loadKeystore(KEYSTORE_FILEPATH, KEYSTORE_PASSWORD);
    }
  }

  @Test
  public void convertStringToDocToString_xmlStr_remainsSame ()
      throws HandlerException, IOException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));
    final String strWithoutFirstLine = str.substring(str.indexOf('\n')+1);

    assertEquals(strWithoutFirstLine,
        convertDocToXMLStr(convertXMLStrToDoc(strWithoutFirstLine)));
  }

  @Test
  public void convertStringToDoc_improperXmlStr_success()
      throws HandlerException {
    convertXMLStrToDoc(SOME_XML);
  }

  @Test (expected = HandlerException.class)
  public void convertStringToDoc_emptyStr_throwsHandlerException ()
      throws HandlerException {
    convertXMLStrToDoc(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void convertStringToDoc_nonXmlStr_throwsHandlerException ()
      throws HandlerException {
    convertXMLStrToDoc(WHITE_SPACE);
  }

  @Test
  public void signXMLPayloadDoc_verifyDecryptedXML_success ()
      throws IOException, HandlerException, XMLSecurityException,
      CertificateEncodingException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate signingCert = handler.getClientSigningCert(KEYSTORE_ALIAS);
    PrivateKey privKey =
        handler.getClientPrivateKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
    Document doc = convertXMLStrToDoc(str);
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
    PrivateKey privKey =
        handler.getClientPrivateKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
    Document doc = convertXMLStrToDoc(str);
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
    PrivateKey privKey =
        handler.getClientPrivateKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
    Document doc = convertXMLStrToDoc(str);
    signXMLPayloadDoc(doc, signingCert, privKey);
    String payloadSignedOnce = convertDocToXMLStr(doc);
    signXMLPayloadDoc(doc, signingCert, privKey);
    String payloadSignedTwice = convertDocToXMLStr(doc);
    assertThat(payloadSignedOnce, not(equalTo(payloadSignedTwice)));
  }

  @Test
  public void decryptEncryptedAndSignedXML_encryptSignedXMLPayloadDoc_remainsSame ()
      throws IOException, HandlerException, XMLEncryptionException {

    org.apache.xml.security.Init.init();

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));

    PublicKey pubKey = handler.getClientSigningCert(KEYSTORE_ALIAS).getPublicKey();
    PrivateKey privKey =
        handler.getClientPrivateKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
    Document encryptedDoc = encryptSignedXMLPayloadDoc(
        convertXMLStrToDoc(str), pubKey);
    String decryptedStr = convertDocToXMLStr(
        decryptEncryptedAndSignedXML(encryptedDoc, privKey));
    assertEquals(str, decryptedStr);
  }

  @Test (expected = HandlerException.class)
  public void decryptEncryptedAndSignedXML_nonEncryptedXml_throwsHandlerException ()
      throws HandlerException, XMLEncryptionException, IOException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));

    PrivateKey privKey =
        handler.getClientPrivateKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
    Document nonEncryptedDoc = convertXMLStrToDoc(str);
    decryptEncryptedAndSignedXML(nonEncryptedDoc, privKey);
  }

  @Test (expected = HandlerException.class)
  public void verifyDecryptedXML_verifySignWithWrongCert_throwsHandlerException ()
      throws HandlerException, XMLSecurityException, CertificateEncodingException,
      IOException {
    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate clientSigningCert =
        handler.getClientSigningCert(KEYSTORE_ALIAS);
    X509Certificate citiSigningCert = getCitiSigningCert();
    PrivateKey privKey =
        handler.getClientPrivateKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD);
    Document doc = convertXMLStrToDoc(str);
    signXMLPayloadDoc(doc, clientSigningCert, privKey);
    verifyDecryptedXML(doc, citiSigningCert);
  }

  @Test (expected = XMLSecurityException.class)
  public void signAndEncryptXMLForCiti_decryptAndVerifyXMLFromCiti_throwsXMLSecurityException ()
      throws IOException, XMLSecurityException, HandlerException,
      CertificateEncodingException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    String signedEncryptedStr = handler.signAndEncryptXMLForCiti(str);
    handler.decryptAndVerifyXMLFromCiti(signedEncryptedStr);
  }

  @Test
  public void parseAuthOrPayInitResponse_AuthResponse_parseSuccess ()
      throws HandlerException, XPathExpressionException, IOException {

    final String authResponse = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/"
            + "XML Response/AuthorizationResponse_Signed.txt")));
    final String oAuthToken = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/"
            + "XML Response/AuthorizationResponse_Token.txt")));

    String oAuthTokenParsed = parseAuthOrPayInitResponse(
        convertXMLStrToDoc(authResponse), TYPE_AUTH, TAG_NAME_AUTH);
    assertEquals(oAuthToken, oAuthTokenParsed);
  }

  @Test
  public void parseAuthOrPayInitResponse_PayInitResponse_parseSuccess ()
      throws HandlerException, XPathExpressionException, IOException {

    final String payInitResponse = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DirectDebitPayment/"
            + "XML Response/DirectDebitResponse_Plain.xml")));
    final String sampleISOXML = new String(Files.readAllBytes(
        Paths.get("src/test/resources/sample/PaymentInitiation/"
            + "DirectDebitPayment/XML Response/"
            + "DirectDebitResponse_ISOXMLPlain.xml")));

    String payInitResponseParsed = parseAuthOrPayInitResponse(
        convertXMLStrToDoc(payInitResponse), TYPE_PAY_INIT, TAG_NAME_PAY_INIT);
    assertEquals(sampleISOXML, payInitResponseParsed);
  }

  @Test
  public void parseAuthOrPayInitResponse_AuthResponse_wrongArgsThrowsException ()
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
        convertXMLStrToDoc(response), TYPE_PAY_INIT, TAG_NAME_AUTH);
    assertThat(oAuthToken, not(equalTo(oAuthTokenParsed)));

    exception.expect(HandlerException.class);
    parseAuthOrPayInitResponse(
        convertXMLStrToDoc(response), TYPE_AUTH, TAG_NAME_PAY_INIT);
    parseAuthOrPayInitResponse(
        convertXMLStrToDoc(response), TYPE_PAY_INIT, TAG_NAME_PAY_INIT);
  }

  @Test
  public void parseAuthOrPayInitResponse_someXml_throwsHandlerException ()
      throws HandlerException, XPathExpressionException {

    exception.expect(HandlerException.class);
    exception.expectMessage("No content extracted from response");
    parseAuthOrPayInitResponse(
        convertXMLStrToDoc(SOME_XML), TYPE_PAY_INIT, TAG_NAME_AUTH);
  }

  @Test
  public void authenticate_responseReceivedSuccess ()
      throws IOException, XMLSecurityException, HandlerException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/XML Request/"
            + "AuthorizationRequest_V3_Plain.txt")));

    handler.requestOAuth(str);
  }

  @Test
  public void authentication_validateAllAPIs_success ()
      throws IOException, XMLSecurityException, HandlerException,
      CertificateEncodingException, XPathExpressionException {

//    final String strAuth = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/Authentication/"
//            + "DirectDebitPaymentandUSFasterPayment/XML Request/"
//            + "AuthorizationRequest_V3_Plain.txt")));
    final String strAuth = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/OutgoingPayment/"
            + "XML Request/AuthorizationRequest_V2_Plain.txt")));
    String response = handler.requestOAuth(strAuth);
    String decryptedVerifiedResponse = handler.decryptAndVerifyXMLFromCiti(response);
    String oAuthToken = parseAuthOrPayInitResponse(
        convertXMLStrToDoc(decryptedVerifiedResponse), TYPE_AUTH, TAG_NAME_AUTH);
    handler.setOAuthToken(oAuthToken);

//    final String strInitPay = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
//            + "XML Request/PaymentInitRequest_ISOXMLPlain_DFT.txt")));
//    final String strInitPay = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/PaymentInitiation/DirectDebitPayment/"
//            + "XML Request/PaymentInitRequest_ISOXMLPlain_FAST.txt")));
//    final String strInitPay = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
//            + "XML Request/DeskeraFastISOXML.txt")));
//    final String resInitPay_Encrypted = handler.initiatePayment(strInitPay);
//    final String resInitPay_Plain =
//        handler.decryptAndVerifyXMLFromCiti(resInitPay_Encrypted);
//    final String resInitPay_ISOXML = parseAuthOrPayInitResponse(
//        convertXMLStrToDoc(resInitPay_Plain), TYPE_PAY_INIT, TAG_NAME_PAY_INIT);
//    System.out.println(resInitPay_ISOXML);
//
    final String strCheckPay = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/EnhancedPaymentStatusInquiry/"
            + "XML Request/paymentInq_Request_EndToEndId.txt")));
    final String resCheckPay_Encrypted = handler.checkPaymentStatus(strCheckPay);
    final String resCheckPay_Plain =
        handler.decryptAndVerifyXMLFromCiti(resCheckPay_Encrypted);
    System.out.println(resCheckPay_Plain);
//
//    final String strCheckBalance = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/BalanceInquiry/"
//            + "XML Request/BalanceInquiryRequest_Plain_Real.txt")));
//    final String resBalance_Encypted = handler.checkBalance(strCheckBalance);
//    final String resBalance =
//        handler.decryptAndVerifyXMLFromCiti(resBalance_Encypted);
//    final String json = readCAMT052ToJson(resBalance);
////    System.out.println(json);
//
//    final String strInitStat = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/StatementInitiation/CAMTorSWIFT/"
//            + "XML Request/StatementInitiationRequest_CAMT_053_001_02_Plain_Real.txt")));
//    final String resInitStat_Encrypted = handler.initiateStatement(strInitStat);
//    final String resInitStat = handler.decryptAndVerifyXMLFromCiti(resInitStat_Encrypted);
//    final String statementId = extractStatementId(resInitStat);
////      System.out.println(statementId);

//    final String strStatRet = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/StatementRetrieval/"
//            + "XML Request/StatementRetrievalRequest_Plain_Format.txt")))
//        .replace("placeholder", "111111114");
//    final String resStatRet = handler.retrieveStatement(
//        strStatRet, STATEMENT_RET_URL_MOCK);
//    System.out.println(resStatRet);
  }

  @Test
  public void generateBase64InputFromISOXMLPayload_success ()
      throws IOException, HandlerException {

    final String payloadSample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_Plain.txt")));
    final String ISOXML = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_ISOXMLPlain.txt")));

    String ISOXML_base64 = generateBase64PayloadFromISOXML(ISOXML);
    assertEquals(payloadSample, ISOXML_base64);
  }

  @Test (expected = HandlerException.class)
  public void generateBase64PayloadFromISOXML_emptyStr_throwsException ()
      throws HandlerException {
    generateBase64PayloadFromISOXML(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void generateBase64PayloadFromISOXML_whiteSpace_throwsException ()
      throws HandlerException {
    generateBase64PayloadFromISOXML(WHITE_SPACE);
  }

  @Test (expected = HandlerException.class)
  public void generateBase64PayloadFromISOXML_nonISOXML_throwsException ()
      throws HandlerException {
    generateBase64PayloadFromISOXML(SOME_XML);
  }

  @Test
  public void parseMIMEResponse_sampleResponse_parseSuccess ()
      throws HandlerException, IOException {

    final byte[] responseSample = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response.txt"));
    final String firstHalfSample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_firstHalf.txt")));
    final byte[] secondHalfSample = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_secondHalf.txt"));

    HashMap<String, Object> body = parseMIMEResponse(responseSample);
    final String firstHalfParsed = (String) body.get("ENCRYPTED_KEY");
    final byte[] secondHalfParsed = (byte[]) body.get("ENCRYPTED_FILE");

    assertEquals(firstHalfSample, firstHalfParsed);
    assertArrayEquals(secondHalfSample, secondHalfParsed);
  }

  @Test
  public void des3DecodeCBC_mockStatement_decryptSuccess ()
      throws HandlerException, IOException {

    final String decryptionKey = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_attachedKey.txt")));
    final byte[] encryptedStatFile = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_secondHalf.txt"));
    final byte[] sampleStatFile = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_secondHalf_Decrypted.txt"));

    byte[] decryptedStatFile = des3DecodeCBC(decryptionKey, encryptedStatFile);
    assertArrayEquals(sampleStatFile, decryptedStatFile);
  }

  @Test (expected = HandlerException.class)
  public void des3DecodeCBC_emptyKey_throwsHandlerException ()
      throws HandlerException, IOException {

    final byte[] encryptedStatFile = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_secondHalf.txt"));

    des3DecodeCBC(EMPTY_STRING, encryptedStatFile);
  }

  @Test (expected = HandlerException.class)
  public void des3DecodeCBC_whiteSpaceKey_throwsHandlerException ()
      throws HandlerException, IOException {

    final byte[] encryptedStatFile = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_secondHalf.txt"));

    des3DecodeCBC(WHITE_SPACE, encryptedStatFile);
  }

  @Test (expected = HandlerException.class)
  public void des3DecodeCBC_invalidKey_throwsHandlerException ()
      throws HandlerException, IOException {

    final byte[] encryptedStatFile = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_secondHalf.txt"));

    des3DecodeCBC(SOME_XML, encryptedStatFile);
  }

  @Test
  public void extractStatementId_sampleResponse_success ()
      throws IOException, HandlerException {
    final String intradayResponse = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementInitiation/Intraday/"
            + "XML Response/StatementInitiationResponse_SWIFT_MT_942_Plain.txt")));

    final String statementId = extractStatementId(intradayResponse);
    assertEquals("42389500", statementId);
  }

  @Test (expected = HandlerException.class)
  public void extractStatementId_emptyStr_throwsHandlerException ()
      throws HandlerException {

    extractStatementId(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void extractStatementId_whiteSpace_throwsHandlerException ()
      throws HandlerException {

    extractStatementId(WHITE_SPACE);
  }

  @Test (expected = HandlerException.class)
  public void extractStatementId_invalidResponse_throwsHandlerException ()
      throws HandlerException {

    extractStatementId(SOME_XML);
  }

  @Test
  public void extractAttachmentDecryptionKey_sampleResponse_success ()
      throws IOException, HandlerException {
    final String xmlResponse = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_firstHalf_Decrypted.txt")));

    final String attachedKey = extractAttachmentDecryptionKey(xmlResponse);
    assertEquals("YC+SA+64lx4OLsNmv66O7AvMABQvA0L0", attachedKey);
  }

  @Test (expected = HandlerException.class)
  public void extractAttachmentDecryptionKey_emptyStr_throwsHandlerException ()
      throws HandlerException {

    extractAttachmentDecryptionKey(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void extractAttachmentDecryptionKey_whiteSpace_throwsHandlerException ()
      throws HandlerException {

    extractAttachmentDecryptionKey(WHITE_SPACE);
  }

  @Test (expected = HandlerException.class)
  public void extractAttachmentDecryptionKey_invalidResponse_throwsHandlerException ()
      throws HandlerException {

    extractAttachmentDecryptionKey(SOME_XML);
  }

}
