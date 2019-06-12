package test.java;

import static main.java.Handler.convertDocToXMLStr;
import static main.java.Handler.convertXMLStrToDoc;
import static main.java.Handler.createPayInitDocumentInstance;
import static main.java.Handler.des3DecodeCBC;
import static main.java.Handler.extractAttachmentDecryptionKey;
import static main.java.Handler.extractStatementId;
import static main.java.Handler.createPayInitPayload;
import static main.java.Handler.decryptEncryptedAndSignedXML;
import static main.java.Handler.encryptSignedXMLPayloadDoc;
import static main.java.Handler.generateBase64PayloadFromISOXML;
import static main.java.Handler.getCitiSigningCert;
import static main.java.Handler.parseAuthOrPayInitResponse;
import static main.java.Handler.parseMIMEResponse;
import static main.java.Handler.readCAMT53ToJson;
import static main.java.Handler.signXMLPayloadDoc;
import static main.java.Handler.verifyDecryptedXML;
import static main.java.HandlerConstant.PAIN_CLASS_PATH;
import static main.java.HandlerConstant.STATEMENT_RET_URL_UAT;
import static main.java.HandlerConstant.TYPE_AUTH;
import static main.java.HandlerConstant.TYPE_PAY_INIT;
import static main.java.HandlerConstant.TAG_NAME_AUTH;
import static main.java.HandlerConstant.TAG_NAME_PAY_INIT;
import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;
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
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import main.java.Handler;
import main.java.HandlerException;
import main.java.XMLJsonConvertor;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

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
      handler.loadKeystore();
    }
  }

//  /**
//   * Tears down the test fixture.
//   * (Called after every test case method.)
//   */
//  @After
//  public void tearDown() {
//    handler = null;
//  }

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

    X509Certificate signingCert = handler.getClientSigningCert();
    PrivateKey privKey = handler.getClientPrivateKey();
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
    PrivateKey privKey = handler.getClientPrivateKey();
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
    PrivateKey privKey = handler.getClientPrivateKey();
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

    PublicKey pubKey = handler.getClientSigningCert().getPublicKey();
    PrivateKey privKey = handler.getClientPrivateKey();
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

    PrivateKey privKey = handler.getClientPrivateKey();
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

    X509Certificate clientSigningCert = handler.getClientSigningCert();
    X509Certificate citiSigningCert = getCitiSigningCert();
    PrivateKey privKey = handler.getClientPrivateKey();
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

    final String strAuth = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/XML Request/"
            + "AuthorizationRequest_V3_Plain.txt")));
    String response = handler.requestOAuth(strAuth);
    String decryptedVerifiedResponse = handler.decryptAndVerifyXMLFromCiti(response);
    String oAuthToken = parseAuthOrPayInitResponse(
        convertXMLStrToDoc(decryptedVerifiedResponse), TYPE_AUTH, TAG_NAME_AUTH);
    handler.setOAuthToken(oAuthToken);

//    final String ISOXMLInitPay = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
//            + "XML Request/PaymentInitRequest_ISOXMLPlain.txt")));
//    String resInitPay_Encrypted = new String(handler.initiatePayment(ISOXMLInitPay));
//    String resInitPay = handler.decryptAndVerifyXMLFromCiti(resInitPay_Encrypted);
//    System.out.println(resInitPay);

    final String strInitStat = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementInitiation/CAMTorSWIFT/"
            + "XML Request/StatementInitiationRequest_CAMT_053_001_02_Plain_Real.txt")));
    final String resInitStat_Encrypted = new String(handler.initiateStatement(strInitStat));
    final String resInitStat = handler.decryptAndVerifyXMLFromCiti(resInitStat_Encrypted);
    final String statementId = extractStatementId(resInitStat);

    final String strStatRet = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/"
            + "XML Request/StatementRetrievalRequest_Plain_Format.txt")))
        .replace("placeholder", statementId);
    String resStatRet = new String(
        handler.retrieveStatement(strStatRet, STATEMENT_RET_URL_UAT));
    System.out.println(resStatRet);

//    final String strBalance = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/BalanceInquiry/"
//            + "XML Request/BalanceInquiryRequest_Plain_Real.txt")));
//    String resBalance_Encypted = handler.checkBalance(strBalance);
//    String resBalance = handler.decryptAndVerifyXMLFromCiti(resBalance_Encypted);
//    System.out.println(resBalance);
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
  public void createPayInitPayload_resultSameAsSample ()
      throws IOException, HandlerException, SAXException {
    final String payloadSample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_ISOXMLPlain.txt")));
    final String payloadCreated = createPayInitPayload();

    assertXMLEqual(payloadSample, payloadCreated);
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

  @Test
  public void readXMLToElement_JAXBElementGeneratedCorrectly ()
      throws IOException, DatatypeConfigurationException, JAXBException {

    main.java.pain.Document document = createPayInitDocumentInstance();
    JAXBElement<main.java.pain.Document> documentElement =
        (new main.java.pain.ObjectFactory()).createDocument(document);

    final String payloadSample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_ISOXMLPlain.txt")));
    XMLJsonConvertor<main.java.pain.Document> convertor =
        new XMLJsonConvertor<>(PAIN_CLASS_PATH);
    JAXBElement<main.java.pain.Document> documentMarshaled =
        convertor.readXMLToElement(payloadSample);

    // TODO use assertEquals to compare all the contents within the two objects
//    assertEquals(documentElement, documentMarshaled);
  }

  @Test
  public void readCAMT53ToJson_sampleCAMT53Sample_readSuccess ()
      throws HandlerException, IOException {

    final String CAMT53Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "StatementRetrieval_CAMT_053_001_02_File.txt")));

    String res = readCAMT53ToJson(CAMT53Sample);

    System.out.println(res);
  }

}
