package test.java;

import static main.java.Handler.convertDocToString;
import static main.java.Handler.convertStringToDoc;
import static main.java.Handler.decryptEncryptedAndSignedXML;
import static main.java.Handler.encryptSignedXMLPayloadDoc;
import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import main.java.HandlerException;
import org.apache.xml.security.encryption.XMLEncryptionException;
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
  public void convertStringToDocToString_xmlStr_remainsSame () {
    try {
      String str = new String(Files.readAllBytes(Paths.get(
          "test/resources/sample/BalanceInquiry/XML Request/"
              + "BalanceInquiryRequest_Signed.txt")));
      assertEquals(str, convertDocToString(convertStringToDoc(str)));
    }
    catch (IOException | HandlerException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void decryptEncryptedAndSignedXML_encryptSignedXMLPayloadDoc_remainsSame () {
    try {

      PKCS8EncodedKeySpec spec =
          new PKCS8EncodedKeySpec(Files.readAllBytes(Paths.get(
              "main/resources/key/deskera/deskera_customer_private.key")));
      KeyFactory kf = KeyFactory.getInstance("RSA");
      PrivateKey clientPrivateKey =kf.generatePrivate(spec);

      X509EncodedKeySpec pspec =
          new X509EncodedKeySpec(Files.readAllBytes(Paths.get(
              "main/resources/key/deskera/deskera_sign_encryption_pubkey.crt")));
      KeyFactory pkf = KeyFactory.getInstance("RSA");
      PublicKey clientPublicKey = pkf.generatePublic(pspec);

      String str = new String(Files.readAllBytes(Paths.get(
          "test/resources/sample/BalanceInquiry/XML Response/"
              + "BalanceInquiryResponse_Plain.txt")));
      Document encryptedDoc = encryptSignedXMLPayloadDoc(
          convertStringToDoc(str), clientPublicKey);
      String decryptedStr = convertDocToString(
          decryptEncryptedAndSignedXML(encryptedDoc, clientPrivateKey));
      assertEquals(str, decryptedStr);

    } catch (IOException | HandlerException | XMLEncryptionException |
        NoSuchAlgorithmException | InvalidKeySpecException e) {
      e.printStackTrace();
    }
  }

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