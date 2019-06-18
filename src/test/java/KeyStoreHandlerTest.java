package test.java;

import static main.java.Handler.convertDocToXMLStr;
import static main.java.Handler.convertXMLStrToDoc;
import static main.java.Handler.decryptEncryptedAndSignedXML;
import static main.java.Handler.encryptSignedXMLPayloadDoc;
import static main.java.Handler.signXMLPayloadDoc;
import static main.java.Handler.verifyDecryptedXML;
import static main.java.KeyStoreHandler.createKeystoreFromCertAndKey;
import static main.java.KeyStoreHandler.deleteP12IfExists;
import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import junit.framework.TestCase;
import main.java.Handler;
import main.java.HandlerException;
import main.java.KeyStoreHandlerException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

@RunWith(JUnit4.class)
public class KeyStoreHandlerTest extends TestCase {

  private final String CTMR_CERT_PATH =
      "src/main/resources/key/deskera/deskera_sign_encryption_pubkey.crt";
  private final String CTMR_KEY_PATH =
      "src/main/resources/key/deskera/deskera_customer_private.key";
  private final String VNDR_CERT_PATH =
      "src/main/resources/key/deskera/deskera_ssl_pubkey.crt";
  private final String VNDR_KEY_PATH =
      "src/main/resources/key/deskera/deskera_vendor_private.key";
  private final String KS_PATH = "src/test/resources/key/as9Jijl4P2Yjhs.p12";
  private final String KS_ALIAS = "alias";
  private final String NONEXSISTENT_KS_PATH = "src/test/resources/key/ha2dTaNfpOn.p12";
  private final String FOLDER_PATH = "src/test/resources/key/";
  private final String KS_PASSWORD = "7NLuioh2zn80";

  @Test
  public void createKeystoreFromCertAndKey_compatibleCertAndKey_createSuccess ()
      throws KeyStoreHandlerException {

    deleteP12IfExists(KS_PATH);
    createKeystoreFromCertAndKey(
        CTMR_CERT_PATH, CTMR_KEY_PATH, KS_PATH, KS_ALIAS, KS_PASSWORD.toCharArray());
    File f = new File(KS_PATH);
    assertTrue(f.exists() && !f.isDirectory());
  }

  @Test
  public void createKeystoreFromCertAndKey_compatibleCertAndKey_decryptVerifySuccess ()
      throws KeyStoreHandlerException, HandlerException, XMLSecurityException,
      CertificateEncodingException, IOException, SAXException {

    deleteP12IfExists(KS_PATH);
    createKeystoreFromCertAndKey(
        CTMR_CERT_PATH, CTMR_KEY_PATH, KS_PATH, KS_ALIAS, KS_PASSWORD.toCharArray());
    File f = new File(KS_PATH);
    assertTrue(f.exists() && !f.isDirectory());

    org.apache.xml.security.Init.init();
    final String sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));
    Handler handler = new Handler();
    handler.loadKeystore(KS_PATH, KS_PASSWORD);
    X509Certificate signCert = handler.getClientSigningCert(KS_ALIAS);
    PublicKey pubKey = handler.getClientSigningCert(KS_ALIAS).getPublicKey();
    PrivateKey privKey = handler.getClientPrivateKey(KS_ALIAS, KS_PASSWORD);
    Document sampleDoc = convertXMLStrToDoc(sample);
    signXMLPayloadDoc(sampleDoc, signCert, privKey);
    String signedSample = convertDocToXMLStr(sampleDoc);
    Document encryptedDoc = encryptSignedXMLPayloadDoc(sampleDoc, pubKey);
    Document decryptedDoc = decryptEncryptedAndSignedXML(encryptedDoc, privKey);
    verifyDecryptedXML(decryptedDoc, signCert);
    String decryptedSample = convertDocToXMLStr(decryptedDoc);
    assertXMLEqual(signedSample, decryptedSample);
  }

  @Test (expected = XMLSecurityException.class)
  public void createKeystoreFromCertAndKey_incompatibleCertAndKey_throwsException ()
      throws KeyStoreHandlerException, HandlerException, IOException,
      XMLSecurityException  {

    deleteP12IfExists(KS_PATH);
    createKeystoreFromCertAndKey(
        VNDR_CERT_PATH, CTMR_KEY_PATH, KS_PATH, KS_ALIAS, KS_PASSWORD.toCharArray());
    File f = new File(KS_PATH);
    assertTrue(f.exists() && !f.isDirectory());

    org.apache.xml.security.Init.init();
    final String sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));
    Handler handler = new Handler();
    handler.loadKeystore(KS_PATH, KS_PASSWORD);
    PublicKey pubKey = handler.getClientSigningCert(KS_ALIAS).getPublicKey();
    PrivateKey privKey = handler.getClientPrivateKey(KS_ALIAS, KS_PASSWORD);
    Document sampleDoc = convertXMLStrToDoc(sample);
    Document encryptedDoc = encryptSignedXMLPayloadDoc(sampleDoc, pubKey);
    decryptEncryptedAndSignedXML(encryptedDoc, privKey);
  }

  @Test
  public void deleteP12IfExists_existingP12_deletionSuccess ()
      throws KeyStoreHandlerException {

    deleteP12IfExists(KS_PATH);
    File f = new File(KS_PATH);
    createKeystoreFromCertAndKey(
        CTMR_CERT_PATH, CTMR_KEY_PATH, KS_PATH, KS_ALIAS, KS_PASSWORD.toCharArray());
    assertTrue(f.exists() && !f.isDirectory());
    deleteP12IfExists(KS_PATH);
    assertFalse(f.exists() && !f.isDirectory());
  }

  @Test
  public void deleteP12IfExists_nonExistentP12_noDeletion ()
      throws KeyStoreHandlerException {
    deleteP12IfExists(NONEXSISTENT_KS_PATH);
  }

  @Test (expected = KeyStoreHandlerException.class)
  public void deleteP12IfExists_nonFile_throwsException ()
      throws KeyStoreHandlerException {
    deleteP12IfExists(FOLDER_PATH);
  }
  
}
