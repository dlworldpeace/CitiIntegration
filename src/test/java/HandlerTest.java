package test.java;

import static main.java.Handler.convertDocToString;
import static main.java.Handler.convertStringToDoc;
import static main.java.Handler.decryptEncryptedAndSignedXML;
import static main.java.Handler.encryptSignedXMLPayloadDoc;
import static main.java.Handler.signXMLPayloadDoc;
import static main.java.Handler.verifyDecryptedXML;
import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import main.java.Handler;
import main.java.HandlerException;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;

public class HandlerTest {

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

    String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));
    String strWithoutFirstLine = str.substring(str.indexOf('\n')+1);

    assertEquals(strWithoutFirstLine,
        convertDocToString(convertStringToDoc(strWithoutFirstLine)));
  }

  @Test
  public void decryptEncryptedAndSignedXML_encryptSignedXMLPayloadDoc_remainsSame ()
      throws IOException, HandlerException, XMLEncryptionException {

    org.apache.xml.security.Init.init();

    String str = new String(Files.readAllBytes(Paths.get(
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
  public void signXMLPayloadDoc_verifyDecryptedXML_success ()
      throws IOException, HandlerException, XMLSecurityException,
      CertificateEncodingException {

    String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain.txt")));

    X509Certificate signingCert = handler.getClientSigningCert();
    PrivateKey privKey = handler.getClientPrivateKey();

    Document doc = convertStringToDoc(str);
    signXMLPayloadDoc(doc, signingCert, privKey);
    verifyDecryptedXML(doc, signingCert);
  }

//  @Test(expected = IndexOutOfBoundsException.class)
//  public void testIndexOutOfBoundsException() {
//    ArrayList emptyList = new ArrayList();
//    Object o = emptyList.get(0);
//  }

//  @Test
//  public void convertStringToDoc() {
//  }
//
//  @Test
//  public void getClientSigningCert() {
//  }
//
//  @Test
//  public void getClientPrivateKey() {
//  }
//
//  @Test
//  public void signXMLPayloadDoc() {
//  }
//
//  @Test
//  public void getCitiPublicKey() {
//  }
//
//  @Test
//  public void encryptSignedXMLPayloadDoc() {
//  }
//
//  @Test
//  public void convertDocToString() {
//  }
//
//  @Test
//  public void signAndEncryptXML() {
//  }
//
//  @Test
//  public void loadKeystoreWithAllCerts() {
//  }
//
//  @Test
//  public void getClientPublicDecrytionKey() {
//  }
//
//  @Test
//  public void getClientPrivateDecryptionKey() {
//  }
//
//  @Test
//  public void decryptEncryptedAndSignedXML() {
//  }
//
//  @Test
//  public void getCitiVerficationKey() {
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
//  public void handleResponse() {
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
//  public void httpHandler() {
//  }
//
//  @Test
//  public void retrieveStatement() {
//  }
}