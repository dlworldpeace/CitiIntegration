package test.java;

import static main.java.Handler.convertDocToString;
import static main.java.Handler.convertStringToDoc;
import static main.java.Handler.decryptEncryptedAndSignedXML;
import static main.java.Handler.encryptSignedXMLPayloadDoc;
import static org.junit.Assert.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import main.java.HandlerException;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;

public class HandlerTest {

//  @BeforeClass
//  public static void setupBeforeClass() throws HandlerException {
//    Handler handler = new Handler();
//    handler.loadKeystore();
//  }

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
      throws IOException, HandlerException, XMLEncryptionException,
      NoSuchAlgorithmException, InvalidKeySpecException, URISyntaxException {

    org.apache.xml.security.Init.init();

    String str = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));

    String privateKeyContent = new String(Files.readAllBytes(
        Paths.get(ClassLoader.getSystemResource(
            "src/main/resources/key/deskera/deskera_customer_private.key").toURI())));
    String publicKeyContent = new String(Files.readAllBytes(
        Paths.get(ClassLoader.getSystemResource(
            "src/main/resources/key/deskera/deskera_pubkey.pem").toURI())));

    privateKeyContent = privateKeyContent.replaceAll("\\n", "")
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "");
    publicKeyContent = publicKeyContent.replaceAll("\\n", "")
        .replace("-----BEGIN PUBLIC KEY-----", "")
        .replace("-----END PUBLIC KEY-----", "");

    KeyFactory kf = KeyFactory.getInstance("RSA");

    PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(
        Base64.getDecoder().decode(privateKeyContent));
    PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

    X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(
        Base64.getDecoder().decode(publicKeyContent));
    PublicKey pubKey = kf.generatePublic(keySpecX509);

    Document encryptedDoc = encryptSignedXMLPayloadDoc(
        convertStringToDoc(str), pubKey);
    String decryptedStr = convertDocToString(
        decryptEncryptedAndSignedXML(encryptedDoc, privKey));
    assertEquals(str, decryptedStr);
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
//  public void getClientPublicKey() {
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