package test.java;

import static main.java.BankFormatConverter.convertCamt052ToJson;
import static main.java.Constant.*;
import static main.java.Handler.condenseErrorResponse;
import static main.java.Handler.convertDocToXmlStr;
import static main.java.Handler.convertXmlStrToDoc;
import static main.java.Handler.decryptEncryptedAndSignedXml;
import static main.java.Handler.des3DecodeCbc;
import static main.java.Handler.encryptSignedXmlPayloadDoc;
import static main.java.Handler.extractAttachmentDecryptionKey;
import static main.java.Handler.extractStatementId;
import static main.java.Handler.generateBase64PayloadFromIsoXml;
import static main.java.Handler.getCitiSigningCert;
import static main.java.Handler.getClientId;
import static main.java.Handler.getSecretKey;
import static main.java.Handler.isPROD;
import static main.java.Handler.parseAuthOrPayInitResponse;
import static main.java.Handler.parseMimeResponse;
import static main.java.Handler.signXmlPayloadDoc;
import static main.java.Handler.verifyDecryptedXml;
import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import javax.xml.xpath.XPathExpressionException;
import main.java.BankFormatConverterException;
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

  private static final String EMPTY_STRING = "";
  private static final String WHITE_SPACE = " ";
  private static final String SOME_XML = "<hi>123</hi>";
  private static final String SAMPLE_ERROR_RESPONSE =
      "<errormessage>\n"
      + "<httpCode>400</httpCode>\n"
      + "<httpMessage>BadRequest</httpMessage>\n"
      + "<moreInformation>Schema Validation Failed</moreInformation>\n"
      + "</errormessage>\n";
  private static final String SAMPLE_CONDENSED_MSG =
      "400. BadRequest. Schema Validation Failed. ";
  private static final String SAMPLE_ERROR_RESPONSE_LESS_INFO =
      "<errormessage>\n"
          + "<httpCode>400</httpCode>\n"
          + "<httpMessage>BadRequest</httpMessage>\n"
          + "</errormessage>\n";
  private static final String SAMPLE_CONDENSED_MSG_LESS_INFO =
      "400. BadRequest. ";

  private Handler handler;
  private String clientId;
  private String secretKey;

  @Rule
  public ExpectedException exception = ExpectedException.none();

  /**
   * Sets up the test fixture.
   * (Called before every test case method.)
   */
  @Before
  public void setUp() throws HandlerException {
    if (handler == null) {
      handler = new Handler();
      if (Handler.isPROD) {
        handler.loadKeystore(KEYSTORE_FILEPATH_PROD, KEYSTORE_PASSWORD_PROD);
      } else {
        handler.loadKeystore(KEYSTORE_FILEPATH_UAT, KEYSTORE_PASSWORD_UAT);
      }
    }
    if (clientId == null) {
      clientId = getClientId();
    }
    if (secretKey == null) {
      secretKey = getSecretKey();
    }
  }

  @Test
  public void convertStringToDocToString_xmlStr_remainsSame()
      throws HandlerException, IOException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));
    final String strWithoutFirstLine = str.substring(str.indexOf('\n') + 1);

    assertEquals(strWithoutFirstLine,
        convertDocToXmlStr(convertXmlStrToDoc(strWithoutFirstLine)));
  }

  @Test
  public void convertStringToDoc_improperXmlStr_success()
      throws HandlerException {
    convertXmlStrToDoc(SOME_XML);
  }

  @Test (expected = HandlerException.class)
  public void convertStringToDoc_emptyStr_throwsHandlerException()
      throws HandlerException {
    convertXmlStrToDoc(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void convertStringToDoc_nonXmlStr_throwsHandlerException()
      throws HandlerException {
    convertXmlStrToDoc(WHITE_SPACE);
  }

  @Test
  public void signXmlPayloadDoc_verifyDecryptedXml_success()
      throws IOException, HandlerException, XMLSecurityException,
      CertificateEncodingException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate signingCert = isPROD
        ? handler.getClientSigningCert(KEYSTORE_ALIAS_PROD)
        : handler.getClientSigningCert(KEYSTORE_ALIAS_UAT);
    PrivateKey privKey = isPROD
        ? handler.getClientPrivateKey(KEYSTORE_ALIAS_PROD, KEYSTORE_PASSWORD_PROD)
        : handler.getClientPrivateKey(KEYSTORE_ALIAS_UAT, KEYSTORE_PASSWORD_UAT);
    Document doc = convertXmlStrToDoc(str);
    signXmlPayloadDoc(doc, signingCert, privKey);
    verifyDecryptedXml(doc, signingCert);
  }

  @Test (expected = HandlerException.class)
  public void signXmlPayloadDoc_wrongPairOfCertAndPrivKey_throwsHandlerException()
      throws IOException, HandlerException, XMLSecurityException,
      CertificateEncodingException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate signingCert = Handler.getCitiSigningCert();
    PrivateKey privKey = isPROD
        ? handler.getClientPrivateKey(KEYSTORE_ALIAS_PROD, KEYSTORE_PASSWORD_PROD)
        : handler.getClientPrivateKey(KEYSTORE_ALIAS_UAT, KEYSTORE_PASSWORD_UAT);
    Document doc = convertXmlStrToDoc(str);
    signXmlPayloadDoc(doc, signingCert, privKey);
    verifyDecryptedXml(doc, signingCert);
  }

  @Test
  public void signXmlPayloadDoc_alreadySignedDoc_throwsHandlerException()
      throws IOException, HandlerException, XMLSecurityException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate signingCert = Handler.getCitiSigningCert();
    PrivateKey privKey = isPROD
        ? handler.getClientPrivateKey(KEYSTORE_ALIAS_PROD, KEYSTORE_PASSWORD_PROD)
        : handler.getClientPrivateKey(KEYSTORE_ALIAS_UAT, KEYSTORE_PASSWORD_UAT);
    Document doc = convertXmlStrToDoc(str);
    signXmlPayloadDoc(doc, signingCert, privKey);
    String payloadSignedOnce = convertDocToXmlStr(doc);
    signXmlPayloadDoc(doc, signingCert, privKey);
    String payloadSignedTwice = convertDocToXmlStr(doc);
    assertThat(payloadSignedOnce, not(equalTo(payloadSignedTwice)));
  }

  @Test
  public void decryptEncryptedAndSignedXml_encryptSignedXmlPayloadDoc_remainsSame()
      throws IOException, HandlerException, XMLEncryptionException {

    org.apache.xml.security.Init.init();

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));

    PublicKey pubKey = isPROD
        ? handler.getClientSigningCert(KEYSTORE_ALIAS_PROD).getPublicKey()
        : handler.getClientSigningCert(KEYSTORE_ALIAS_UAT).getPublicKey();
    PrivateKey privKey = isPROD
        ? handler.getClientPrivateKey(KEYSTORE_ALIAS_PROD, KEYSTORE_PASSWORD_PROD)
        : handler.getClientPrivateKey(KEYSTORE_ALIAS_UAT, KEYSTORE_PASSWORD_UAT);
    Document encryptedDoc = encryptSignedXmlPayloadDoc(
        convertXmlStrToDoc(str), pubKey);
    String decryptedStr = convertDocToXmlStr(
        decryptEncryptedAndSignedXml(encryptedDoc, privKey));
    assertEquals(str, decryptedStr);
  }

  @Test (expected = HandlerException.class)
  public void decryptEncryptedAndSignedXml_nonEncryptedXml_throwsHandlerException()
      throws HandlerException, XMLEncryptionException, IOException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));

    PrivateKey privKey = isPROD
        ? handler.getClientPrivateKey(KEYSTORE_ALIAS_PROD, KEYSTORE_PASSWORD_PROD)
        : handler.getClientPrivateKey(KEYSTORE_ALIAS_UAT, KEYSTORE_PASSWORD_UAT);
    Document nonEncryptedDoc = convertXmlStrToDoc(str);
    decryptEncryptedAndSignedXml(nonEncryptedDoc, privKey);
  }

  @Test (expected = HandlerException.class)
  public void verifyDecryptedXml_verifySignWithWrongCert_throwsHandlerException()
      throws HandlerException, XMLSecurityException, CertificateEncodingException,
      IOException {
    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate clientSigningCert = isPROD
        ? handler.getClientSigningCert(KEYSTORE_ALIAS_PROD)
        : handler.getClientSigningCert(KEYSTORE_ALIAS_UAT);
    X509Certificate citiSigningCert = getCitiSigningCert();
    PrivateKey privKey = isPROD
        ? handler.getClientPrivateKey(KEYSTORE_ALIAS_PROD, KEYSTORE_PASSWORD_PROD)
        : handler.getClientPrivateKey(KEYSTORE_ALIAS_UAT, KEYSTORE_PASSWORD_UAT);
    Document doc = convertXmlStrToDoc(str);
    signXmlPayloadDoc(doc, clientSigningCert, privKey);
    verifyDecryptedXml(doc, citiSigningCert);
  }

  @Test (expected = XMLSecurityException.class)
  public void signAndEncryptXmlForCiti_decryptAndVerifyXmlFromCiti_throwsException()
      throws IOException, XMLSecurityException, HandlerException,
      CertificateEncodingException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    String signedEncryptedStr = handler.signAndEncryptXmlForCiti(str);
    handler.decryptAndVerifyXmlFromCiti(signedEncryptedStr);
  }

  @Test
  public void parseAuthOrPayInitResponse_AuthResponse_parseSuccess()
      throws HandlerException, XPathExpressionException, IOException {

    final String authResponse = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/"
            + "XML Response/AuthorizationResponse_Signed.txt")));
    final String oAuthToken = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/"
            + "XML Response/AuthorizationResponse_Token.txt")));

    String oauthTokenParsed = parseAuthOrPayInitResponse(
        convertXmlStrToDoc(authResponse), TYPE_AUTH, TAG_NAME_AUTH);
    assertEquals(oAuthToken, oauthTokenParsed);
  }

  @Test
  public void parseAuthOrPayInitResponse_PayInitResponse_parseSuccess()
      throws HandlerException, XPathExpressionException, IOException {

    final String payInitResponse = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DirectDebitPayment/"
            + "XML Response/DirectDebitResponse_Plain.xml")));
    final String sampleIsoXml = new String(Files.readAllBytes(
        Paths.get("src/test/resources/sample/PaymentInitiation/"
            + "DirectDebitPayment/XML Response/"
            + "DirectDebitResponse_ISOXMLPlain.xml")));

    String payInitResponseParsed = parseAuthOrPayInitResponse(
        convertXmlStrToDoc(payInitResponse), TYPE_PAY_INIT, TAG_NAME_PAY_INIT);
    assertEquals(sampleIsoXml, payInitResponseParsed);
  }

  @Test
  public void parseAuthOrPayInitResponse_AuthResponse_wrongArgsThrowsException()
      throws HandlerException, XPathExpressionException, IOException {

    final String response = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/"
            + "XML Response/AuthorizationResponse_Signed.txt")));
    final String oAuthToken = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/"
            + "XML Response/AuthorizationResponse_Token.txt")));

    String oauthTokenParsed = parseAuthOrPayInitResponse(
        convertXmlStrToDoc(response), TYPE_PAY_INIT, TAG_NAME_AUTH);
    assertThat(oAuthToken, not(equalTo(oauthTokenParsed)));

    exception.expect(HandlerException.class);
    parseAuthOrPayInitResponse(
        convertXmlStrToDoc(response), TYPE_AUTH, TAG_NAME_PAY_INIT);
    parseAuthOrPayInitResponse(
        convertXmlStrToDoc(response), TYPE_PAY_INIT, TAG_NAME_PAY_INIT);
  }

  @Test
  public void parseAuthOrPayInitResponse_someXml_throwsHandlerException()
      throws HandlerException, XPathExpressionException {

    exception.expect(HandlerException.class);
    exception.expectMessage("No content extracted from response");
    parseAuthOrPayInitResponse(
        convertXmlStrToDoc(SOME_XML), TYPE_PAY_INIT, TAG_NAME_AUTH);
  }

  @Test
  public void authenticate_responseReceivedSuccess()
      throws IOException, HandlerException {

    final String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/"
            + "DirectDebitPaymentandUSFasterPayment/XML Request/"
            + "AuthorizationRequest_V3_Plain.txt")));

    handler.requestOAuth(clientId, secretKey, str);
  }

  @Test
  public void authentication_validateAllApi_success() throws IOException,
      XMLSecurityException, HandlerException, CertificateEncodingException,
      XPathExpressionException, BankFormatConverterException {

//    final String strAuth = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/Authentication/"
//            + "DirectDebitPaymentandUSFasterPayment/XML Request/"
//            + "AuthorizationRequest_V3_Plain.txt")));
    final String strAuth = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/Authentication/OutgoingPayment/"
            + "XML Request/AuthorizationRequest_V2_Plain.txt")));
    handler.requestOAuth(clientId, secretKey, strAuth);

    final String strInitPay = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_ISOXMLPlain_DFT.txt")));
//    final String strInitPay = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/PaymentInitiation/DirectDebitPayment/"
//            + "XML Request/PaymentInitRequest_ISOXMLPlain_FAST.txt")));
//    final String strInitPay = new String(Files.readAllBytes(Paths.get(
//        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
//            + "XML Request/DeskeraFastISOXML.txt")));
    final String resInitPay = handler.initiatePayment(clientId, strInitPay);
    System.out.println(resInitPay);

//    final String resCheckPay = handler.checkPaymentStatus(clientId, "SGD123");
//    System.out.println(resCheckPay);

    final String strCheckBalance = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/"
            + "XML Request/BalanceInquiryRequest_Plain_Real.txt")));
    final String resBalance_Encypted = handler.checkBalance(clientId, strCheckBalance);
    final String resBalance =
        handler.decryptAndVerifyXmlFromCiti(resBalance_Encypted);
    final String json = convertCamt052ToJson(resBalance);
    System.out.println(json);

    final String strInitStat = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementInitiation/CAMTorSWIFT/"
            + "XML Request/StatementInitiationRequest_CAMT_053_001_02_Plain_Real.txt")));
    final String resInitStat_Encrypted = handler.initiateStatement(clientId, strInitStat);
    final String resInitStat = handler.decryptAndVerifyXmlFromCiti(resInitStat_Encrypted);
    final String statementId = extractStatementId(resInitStat);
    System.out.println(statementId);

    final String strStatRet = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/"
            + "XML Request/StatementRetrievalRequest_Plain_Format.txt")))
        .replace("placeholder", "111111114");
    final String resStatRet = handler.retrieveStatement(
        clientId, strStatRet, STATEMENT_RET_URL_MOCK);
    System.out.println(resStatRet);
  }

  @Test (expected = HandlerException.class)
  public void authenticateNotDone_callOtherApi_throwsException()
      throws IOException, HandlerException, XMLSecurityException,
      CertificateEncodingException, BankFormatConverterException {
    handler = new Handler();
    final String strCheckBalance = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/"
            + "XML Request/BalanceInquiryRequest_Plain_Real.txt")));
    final String resBalance_Encypted = handler.checkBalance(clientId, strCheckBalance);
    final String resBalance =
        handler.decryptAndVerifyXmlFromCiti(resBalance_Encypted);
    final String json = convertCamt052ToJson(resBalance);
    System.out.println(json);
  }

  @Test
  public void generateBase64InputFromIsoXmlPayload_success()
      throws IOException, HandlerException {

    final String payloadSample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_Plain.txt")));
    final String isoXml = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_ISOXMLPlain.txt")));

    String isoXmlBase64 = generateBase64PayloadFromIsoXml(isoXml);
    assertEquals(payloadSample, isoXmlBase64);
  }

  @Test (expected = HandlerException.class)
  public void generateBase64PayloadFromIsoXml_emptyStr_throwsException()
      throws HandlerException {
    generateBase64PayloadFromIsoXml(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void generateBase64PayloadFromIsoXml_whiteSpace_throwsException()
      throws HandlerException {
    generateBase64PayloadFromIsoXml(WHITE_SPACE);
  }

  @Test (expected = HandlerException.class)
  public void generateBase64PayloadFromIsoXml_nonIsoXml_throwsException()
      throws HandlerException {
    generateBase64PayloadFromIsoXml(SOME_XML);
  }

  @Test
  public void parseMimeResponse_sampleResponse_parseSuccess()
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

    HashMap<String, Object> body = parseMimeResponse(responseSample);
    final String firstHalfParsed = (String) body.get("ENCRYPTED_KEY");
    final byte[] secondHalfParsed = (byte[]) body.get("ENCRYPTED_FILE");

    assertEquals(firstHalfSample, firstHalfParsed);
    assertArrayEquals(secondHalfSample, secondHalfParsed);
  }

  @Test
  public void des3DecodeCbc_mockStatement_decryptSuccess()
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

    byte[] decryptedStatFile = des3DecodeCbc(decryptionKey, encryptedStatFile);
    assertArrayEquals(sampleStatFile, decryptedStatFile);
  }

  @Test (expected = HandlerException.class)
  public void des3DecodeCbc_emptyKey_throwsHandlerException()
      throws HandlerException, IOException {

    final byte[] encryptedStatFile = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_secondHalf.txt"));

    des3DecodeCbc(EMPTY_STRING, encryptedStatFile);
  }

  @Test (expected = HandlerException.class)
  public void des3DecodeCbc_whiteSpaceKey_throwsHandlerException()
      throws HandlerException, IOException {

    final byte[] encryptedStatFile = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_secondHalf.txt"));

    des3DecodeCbc(WHITE_SPACE, encryptedStatFile);
  }

  @Test (expected = HandlerException.class)
  public void des3DecodeCbc_invalidKey_throwsHandlerException()
      throws HandlerException, IOException {

    final byte[] encryptedStatFile = Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_secondHalf.txt"));

    des3DecodeCbc(SOME_XML, encryptedStatFile);
  }

  @Test
  public void extractStatementId_sampleResponse_success()
      throws IOException, HandlerException {
    final String intradayResponse = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementInitiation/Intraday/"
            + "XML Response/StatementInitiationResponse_SWIFT_MT_942_Plain.txt")));

    final String statementId = extractStatementId(intradayResponse);
    assertEquals("42389500", statementId);
  }

  @Test (expected = HandlerException.class)
  public void extractStatementId_emptyStr_throwsHandlerException()
      throws HandlerException {

    extractStatementId(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void extractStatementId_whiteSpace_throwsHandlerException()
      throws HandlerException {

    extractStatementId(WHITE_SPACE);
  }

  @Test (expected = HandlerException.class)
  public void extractStatementId_invalidResponse_throwsHandlerException()
      throws HandlerException {

    extractStatementId(SOME_XML);
  }

  @Test
  public void extractAttachmentDecryptionKey_sampleResponse_success()
      throws IOException, HandlerException {
    final String xmlResponse = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "response_firstHalf_Decrypted.txt")));

    final String attachedKey = extractAttachmentDecryptionKey(xmlResponse);
    assertEquals("YC+SA+64lx4OLsNmv66O7AvMABQvA0L0", attachedKey);
  }

  @Test (expected = HandlerException.class)
  public void extractAttachmentDecryptionKey_emptyStr_throwsHandlerException()
      throws HandlerException {

    extractAttachmentDecryptionKey(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void extractAttachmentDecryptionKey_whiteSpace_throwsHandlerException()
      throws HandlerException {

    extractAttachmentDecryptionKey(WHITE_SPACE);
  }

  @Test (expected = HandlerException.class)
  public void extractAttachmentDecryptionKey_invalidResponse_throwsHandlerException()
      throws HandlerException {

    extractAttachmentDecryptionKey(SOME_XML);
  }

  @Test
  public void condenseErrorResponse_sampleErrorResponse_success()
      throws HandlerException {
    String condensedMsg = condenseErrorResponse(SAMPLE_ERROR_RESPONSE);
    assertEquals(SAMPLE_CONDENSED_MSG, condensedMsg);
  }

  @Test
  public void condenseErrorResponse_sampleErrorResponseWithoutMoreInfo_success()
      throws HandlerException {
    String condensedMsg = condenseErrorResponse(SAMPLE_ERROR_RESPONSE_LESS_INFO);
    assertEquals(SAMPLE_CONDENSED_MSG_LESS_INFO, condensedMsg);
  }

  @Test (expected = HandlerException.class)
  public void condenseErrorResponse_nonErrorResponse_throwsException()
      throws HandlerException {
    condenseErrorResponse(SOME_XML);
  }

  @Test (expected = HandlerException.class)
  public void condenseErrorResponse_emptyStr_throwsException()
      throws HandlerException {
    condenseErrorResponse(EMPTY_STRING);
  }

  @Test (expected = HandlerException.class)
  public void condenseErrorResponse_whiteSpace_throwsException()
      throws HandlerException {
    condenseErrorResponse(WHITE_SPACE);
  }
}
