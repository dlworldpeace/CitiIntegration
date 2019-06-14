package main.java;

import static main.java.HandlerConstant.BALANCE_INQUIRY_URL_UAT;
import static main.java.HandlerConstant.CAMT052_CLASS_PATH;
import static main.java.HandlerConstant.CAMT053_CLASS_PATH;
import static main.java.HandlerConstant.CITI_SSL_CERT_FILE_PATH;
import static main.java.HandlerConstant.CITI_SSL_CERT_PWD;
import static main.java.HandlerConstant.KEYSTORE_ALIAS;
import static main.java.HandlerConstant.KEYSTORE_FILEPATH;
import static main.java.HandlerConstant.KEYSTORE_PASSWORD;
import static main.java.HandlerConstant.OUTGOING_PAYMENT_TYPE;
import static main.java.HandlerConstant.OAUTH_URL_UAT;
import static main.java.HandlerConstant.PAIN001_CLASS_PATH;
import static main.java.HandlerConstant.PAY_INIT_URL_UAT;
import static main.java.HandlerConstant.PAYMENT_TYPE_HEADER;
import static main.java.HandlerConstant.DESKERA_SSL_CERT_FILE_PATH;
import static main.java.HandlerConstant.DESKERA_SSL_CERT_PWD;
import static main.java.HandlerConstant.STATEMENT_INIT_URL_UAT;
import static org.apache.commons.io.IOUtils.toByteArray;
import static org.springframework.http.MediaType.APPLICATION_OCTET_STREAM;
import static org.springframework.http.MediaType.APPLICATION_XML;
import static org.springframework.http.MediaType.TEXT_XML_VALUE;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import javax.mail.util.SharedByteArrayInputStream;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import javax.ws.rs.core.HttpHeaders;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import deskera.fintech.pain001.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.ElementProxy;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * This API supports all connection features to CitiConnect.
 *
 * @author Sagar Mahamuni and Xiao Delong.
 * @version 1.0
 * @since 2019-05-22.
 */

public class Handler {

  /* Instance Variables */

  private String oAuthToken;
  private KeyStore ks;

  /* Setters */

  public void setOAuthToken (String oAuthToken) {
    this.oAuthToken = oAuthToken;
  }

  /* Keys */

  /**
   * get client id to be used in request header.
   *
   * @return client id.
   * @throws HandlerException custom exception for Handler class.
   */
  public static String getClientId () throws HandlerException {
    try {
      return new String(Files.readAllBytes(Paths.get(
          "src/main/resources/key/deskera/deskera_client_id.txt"))).trim();
    } catch (IOException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * get client secret key to be used in request header.
   *
   * @return client secret key.
   * @throws HandlerException custom exception for Handler class.
   */
  public static String getSecretKey () throws HandlerException {
    try {
      return new String(Files.readAllBytes(Paths.get(
          "src/main/resources/key/deskera/deskera_secret_key.txt"))).trim();
    } catch (IOException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Load Keystore file that has all certs.
   *
   * @throws HandlerException custom exception for Handler class.
   */
  public void loadKeystore () throws HandlerException {
    try {
      ks = KeyStore.getInstance("PKCS12");
      FileInputStream fis = new FileInputStream(KEYSTORE_FILEPATH);
      ks.load(fis, KEYSTORE_PASSWORD.toCharArray());
      fis.close();
    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException
        | IOException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Getting public client signing cert.
   *
   * @return client signing cert.
   * @throws HandlerException custom exception for Handler class.
   */
  public X509Certificate getClientSigningCert () throws HandlerException {
    try {
      X509Certificate signCert = (X509Certificate) ks
          .getCertificate(KEYSTORE_ALIAS);
      signCert.checkValidity();
      return signCert;
    } catch (CertificateNotYetValidException | CertificateExpiredException |
        KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Getting private client signing Key.
   *
   * @return PrivateKey client private key.
   * @throws HandlerException custom exception for Handler class.
   */
  public PrivateKey getClientPrivateKey () throws HandlerException {
    try {
      return (PrivateKey) ks.getKey(KEYSTORE_ALIAS, KEYSTORE_PASSWORD.toCharArray());
    } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Getting public citi encryption public key.
   *
   * @return citi public key.
   * @throws HandlerException custom exception for Handler class.
   */
  public static PublicKey getCitiPublicKey () throws HandlerException {
    try {
      CertificateFactory fact = CertificateFactory.getInstance("X.509");
      FileInputStream is = new FileInputStream (
          "src/main/resources/key/citi/citi_encryption_uat.pem");
      X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
      return cer.getPublicKey();
    } catch (IOException | CertificateException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }


  /**
   * Getting public citi verification key.
   *
   * @return public citi verification key.
   * @throws HandlerException custom exception for Handler class.
   */
  public static X509Certificate getCitiSigningCert () throws HandlerException {
    try {
      CertificateFactory fact = CertificateFactory.getInstance("X.509");
      FileInputStream is = new FileInputStream (
          "src/main/resources/key/citi/citi_signature_uat.pem");
      return (X509Certificate) fact.generateCertificate(is);
    } catch (CertificateException | FileNotFoundException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /* Encryption and Decryption Logics */

  /**
   * Getting the XML payload as Document object.
   *
   * @param xmlPayload original payload in xml format.
   * @return converted document object.
   * @throws HandlerException custom exception for Handler class.
   */
  public static Document convertXMLStrToDoc (String xmlPayload)
      throws HandlerException {

    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setNamespaceAware(true);
    try {
      DocumentBuilder builder = factory.newDocumentBuilder();
      return builder.parse(new InputSource(new StringReader(xmlPayload)));
    } catch (ParserConfigurationException | IOException | SAXException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Convert the Document object to String value.
   *
   * @return xml string value of the document WITHOUT the xml header.
   * @throws HandlerException custom exception for Handler class.
   */
  public static String convertDocToXMLStr (Document xmlDoc) throws HandlerException {
    try {
      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer transformer = tf.newTransformer();
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      StringWriter writer = new StringWriter();
      transformer.transform(new DOMSource(xmlDoc), new StreamResult(writer));
      return writer.getBuffer().toString();
    } catch (TransformerException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Signing the XML payload document.
   *
   * @param xmlDoc xml document to be signed.
   * @param signCert certificate to be added in.
   * @param privateSignKey private key used to sign the document.
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the {@code xmlDoc}.
   */
  public static void signXMLPayloadDoc (Document xmlDoc, X509Certificate signCert,
      PrivateKey privateSignKey) throws XMLSecurityException {
    org.apache.xml.security.Init.init();
    ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware(true);
    Element root = xmlDoc.getDocumentElement();
    XMLSignature sig = new XMLSignature(xmlDoc, "file:",
        XMLSignature.ALGO_ID_SIGNATURE_RSA);
    root.appendChild(sig.getElement());
    Transforms transforms = new Transforms(xmlDoc);
    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
    transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
    sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
    KeyInfo info = sig.getKeyInfo();
    X509Data x509data = new X509Data(xmlDoc);
    x509data.add(new XMLX509IssuerSerial(xmlDoc, signCert));
    x509data.add(new XMLX509Certificate(xmlDoc, signCert));
    info.add(x509data);
    sig.sign(privateSignKey);
  }

  /**
   * Encrypt the signed XML payload document
   *
   * @param signedXmlDoc signed XML document.
   * @param publicEncryptKey public key used to encrypt the doc.
   * @throws XMLEncryptionException if an unexpected exception occurs while
   *                                encrypting the signed doc.
   * @throws HandlerException custom exception for Handler class.
   */
  public static Document encryptSignedXMLPayloadDoc (Document signedXmlDoc,
      PublicKey publicEncryptKey) throws XMLEncryptionException, HandlerException {

    String jceAlgorithmName = "DESede";
    Key symmetricKey;

    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
      symmetricKey = keyGenerator.generateKey();
    } catch (NoSuchAlgorithmException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }

    String algorithmURI = XMLCipher.RSA_v1dot5;
    XMLCipher keyCipher = XMLCipher.getInstance(algorithmURI);
    keyCipher.init(XMLCipher.WRAP_MODE, publicEncryptKey);
    EncryptedKey encryptedKey = keyCipher
        .encryptKey(signedXmlDoc, symmetricKey);
    Element rootElement = signedXmlDoc.getDocumentElement();
    algorithmURI = XMLCipher.TRIPLEDES;
    XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
    xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
    EncryptedData encryptedData = xmlCipher.getEncryptedData();
    KeyInfo keyInfo = new KeyInfo(signedXmlDoc);
    keyInfo.add(encryptedKey);
    encryptedData.setKeyInfo(keyInfo);

    try {
      return xmlCipher.doFinal(signedXmlDoc, rootElement, false);
    } catch (Exception e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Sign xml payload using our private key and citi cert, followed by encrypting
   * it using citi public key.
   *
   * @param payloadXML payload string in xml.
   * @return encrypted signed payload string.
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload.
   * @throws HandlerException custom exception for Handler class.
   */
  public String signAndEncryptXMLForCiti (String payloadXML)
      throws XMLSecurityException, HandlerException {
    Document payloadDoc = convertXMLStrToDoc(payloadXML);
    PrivateKey clientPrivateKey = getClientPrivateKey();
    X509Certificate clientSigningCert = getClientSigningCert();
    signXMLPayloadDoc(payloadDoc, clientSigningCert, clientPrivateKey);
    PublicKey citiPublicKey = getCitiPublicKey();
    Document encryptedSignedXMLPayloadDoc = encryptSignedXMLPayloadDoc(
        payloadDoc, citiPublicKey);
    return convertDocToXMLStr(encryptedSignedXMLPayloadDoc);
  }

  /**
   * Decrypt the encrypted & signed xml response payload document.
   *
   * @param encryptedSignedDoc encrypted & signed XML doc from server.
   * @param privateDecryptKey client private key.
   * @return decrypted xml document that is yet verified.
   * @throws XMLEncryptionException if an unexpected exception occurs while
   *                                decrypting the encrypted & signed doc.
   * @throws HandlerException custom exception for Handler class.
   */
  public static Document decryptEncryptedAndSignedXML (Document encryptedSignedDoc,
      PrivateKey privateDecryptKey) throws XMLEncryptionException, HandlerException {

    org.apache.xml.security.Init.init();
    Element docRoot = encryptedSignedDoc.getDocumentElement();
    Node dataEL;
    Node keyEL;
    if ("http://www.w3.org/2001/04/xmlenc#".equals(docRoot.getNamespaceURI())
        && "EncryptedData".equals(docRoot.getLocalName())) {
      dataEL = docRoot;
    } else {
      NodeList childs = docRoot
          .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#",
              "EncryptedData");
      if (childs == null || childs.getLength() == 0) {
        throw new HandlerException(
            "Encrypted Data not found on XML Document while parsing to decrypt");
      }
      dataEL = childs.item(0);
    }
    if (dataEL == null) {
      throw new HandlerException(
          "Encrypted Data not found on XML Document while parsing to decrypt");
    }
    NodeList keyList = ((Element) dataEL)
        .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#",
            "EncryptedKey");
    if (keyList == null || keyList.getLength() == 0) {
      throw new HandlerException(
          "Encrypted Key not found on XML Document while parsing to decrypt");
    }
    keyEL = keyList.item(0);
    XMLCipher cipher = XMLCipher.getInstance();
    cipher.init(XMLCipher.DECRYPT_MODE, null);
    EncryptedData encryptedData = cipher
        .loadEncryptedData(encryptedSignedDoc, (Element) dataEL);
    EncryptedKey encryptedKey = cipher
        .loadEncryptedKey(encryptedSignedDoc, (Element) keyEL);
    if (encryptedData != null && encryptedKey != null) {
      String encAlgoURL = encryptedData.getEncryptionMethod().getAlgorithm();
      XMLCipher keyCipher = XMLCipher.getInstance();
      keyCipher.init(XMLCipher.UNWRAP_MODE, privateDecryptKey);
      Key encryptionKey = keyCipher.decryptKey(encryptedKey, encAlgoURL);
      cipher = XMLCipher.getInstance();
      cipher.init(XMLCipher.DECRYPT_MODE, encryptionKey);
      try {
        Document decryptedDoc = cipher
            .doFinal(encryptedSignedDoc, (Element) dataEL);
        decryptedDoc.normalize();
        return decryptedDoc;
      } catch (Exception e) {
        Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
        throw new HandlerException(e.getMessage());
      }
    } else
      throw new HandlerException("No encrypted data or encrypted key to proceed "
          + "with decrypting the response XML");

  }

  /**
   * Verifying the Signature of decrypted XML response Payload Document.
   *
   * @param decryptedDoc decrypted XML doc to be verified.
   * @param signVerifyCert certificate used to verify the signature of the doc.
   * @throws CertificateEncodingException if an unexpected exception occurs while
   *                                      extracting cert info.
   * @throws XMLSecurityException if an unexpected exception occurs while
   *                              verifying the signature.
   * @throws HandlerException custom exception for Handler class.
   */
  public static void verifyDecryptedXML (Document decryptedDoc,
      X509Certificate signVerifyCert) throws CertificateEncodingException,
      XMLSecurityException, HandlerException {

    boolean verifySignStatus = false;
    NodeList sigElement = decryptedDoc
        .getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#",
            "Signature");
    if (sigElement == null || sigElement.getLength() == 0) {
      throw new HandlerException(
          "No XML Digital Signature Found - unable to check the signature");
    } else {
      String BaseURI = "file:";
      XMLSignature signature = new XMLSignature((Element) sigElement.item(0),
          BaseURI);
      KeyInfo keyInfo = signature.getKeyInfo();
      if (keyInfo == null) {
        throw new HandlerException(
            "Could not locate KeyInfo element - unable to check the signature");
      } else {
        if (keyInfo.containsX509Data()) {
          X509Certificate certFromDoc = keyInfo.getX509Certificate();
          if (certFromDoc != null) {
            int enCodeCertLengthFrmDocCert = certFromDoc.getEncoded().length;
            int enCodeCertLengthTobeValidated = signVerifyCert.getEncoded().length;
            if (enCodeCertLengthFrmDocCert == enCodeCertLengthTobeValidated) {
              verifySignStatus = signature.checkSignatureValue(signVerifyCert);
            } else {
              throw new HandlerException(
                  "Signature Verification Failed as Cert available in XML & "
                      + "configured on Plugin Properties are different");
            }
          }
        } else {
          PublicKey pk = keyInfo.getPublicKey();
          if (pk != null) {
            verifySignStatus = signature.checkSignatureValue(signVerifyCert);
          } else {
            throw new HandlerException(
                "X509 cert and PublicKey not found on signature of XML");
          }
        }
      }
    }
    if (!verifySignStatus) {
      throw new HandlerException("XML Signature Verification Failed");
    }
  }

  /**
   * Decrypt a received xml response first using client private key and then
   * verify its authentication using citi's public verifying certificate.
   *
   * @param encryptedSignedXMLResponse xml response to be decrypted followed by
   *                                   verified.
   * @return verified and decrypted xml response string.
   * @throws CertificateEncodingException if an unexpected exception occurs while
   *                                      extracting cert info.
   * @throws XMLSecurityException if an unexpected exception occurs while
   *                              verifying the signature.
   * @throws HandlerException custom exception for Handler class.
   */
  public String decryptAndVerifyXMLFromCiti (String encryptedSignedXMLResponse)
      throws HandlerException, XMLSecurityException, CertificateEncodingException {
    PrivateKey clientPrivateDecryptionKey = getClientPrivateKey();
    Document encryptedSignedXMLResponseDoc =
        convertXMLStrToDoc(encryptedSignedXMLResponse);
    Document SignedXMLResponseDoc = decryptEncryptedAndSignedXML(
        encryptedSignedXMLResponseDoc, clientPrivateDecryptionKey);
    X509Certificate citiVerificationKey = getCitiSigningCert();
    verifyDecryptedXML(SignedXMLResponseDoc, citiVerificationKey);
    return convertDocToXMLStr(SignedXMLResponseDoc);
  }

  /* API Calling Logics */

  /**
   * Abstraction of HTTP client webservice logic.
   *
   * @param uri URL of the server for sending the http request to.
   * @param signedEncryptedXMLPayload signed and encrypted XML payload
   * @return a HashMap of the response segmented with keys of HEADER, STATUS and
   *         BODY.
   * @throws RestClientException if an unexpected exception occurs while sending
   *                             the http request in exchange for http response.
   */
  public HashMap<String, Object> handleHttp (Map<String, String> headerList,
      String signedEncryptedXMLPayload, String uri) throws RestClientException {

    HashMap<String, Object> response = new HashMap<>();
    try {
      RestTemplate restTemplate = new RestTemplate();
      org.springframework.http.HttpHeaders headers =
          new org.springframework.http.HttpHeaders();
      headers.setAccept(Arrays.asList(APPLICATION_XML, APPLICATION_OCTET_STREAM));
      for (Map.Entry<String, String> entry : headerList.entrySet()) {
        headers.set(entry.getKey(), entry.getValue());
      }
      HttpEntity<String> entity =
          new HttpEntity<>(signedEncryptedXMLPayload, headers);
      ResponseEntity<?> responseEntity = restTemplate
          .exchange(uri, HttpMethod.POST, entity, byte[].class);
      response.put("HEADER", responseEntity.getHeaders());
      response.put("STATUS", responseEntity.getStatusCode());
      response.put("BODY", responseEntity.getBody());
    } catch (HttpStatusCodeException e) {
      response.put("HEADER", e.getResponseHeaders());
      response.put("STATUS", e.getStatusCode());
      response.put("BODY", e.getStatusText()); //.getResponseBodyAsByteArray());
    }
    return response;
  }

  /**
   * Authentication Calling Logic: establish handshake through keys.
   *
   * @param oAuthPayload request body in xml.
   * @return response received from the successful handshake with Citi API.
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload.
   * @throws HandlerException custom exception for Handler class.
   */
  public String requestOAuth (String oAuthPayload) throws XMLSecurityException,
      HandlerException {
    try {
      KeyStore clientStore = KeyStore.getInstance("PKCS12");
      clientStore.load(new FileInputStream(DESKERA_SSL_CERT_FILE_PATH),
          DESKERA_SSL_CERT_PWD.toCharArray());
      KeyManagerFactory kmf = KeyManagerFactory
          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(clientStore, DESKERA_SSL_CERT_PWD.toCharArray());

      KeyStore trustStore = KeyStore.getInstance("JKS");
      trustStore.load(new FileInputStream(CITI_SSL_CERT_FILE_PATH),
          CITI_SSL_CERT_PWD.toCharArray());
      TrustManagerFactory tmf = TrustManagerFactory
          .getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);

      SSLContext sslContext = SSLContext
          .getInstance("TLSv1.2"); // The SSL standard
      sslContext.init(
          kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
      HttpsURLConnection
          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());

      String payload_SignedEncrypted = signAndEncryptXMLForCiti(oAuthPayload);
      Map<String, String> headerList = new HashMap<>();
      headerList.put("Content-Type", "application/xml");
      headerList.put(HttpHeaders.AUTHORIZATION, "Basic "
          + Base64.encodeBase64String((getClientId() + ":" + getSecretKey())
          .getBytes()).replaceAll("([\\r\\n])", ""));
      HashMap<String, Object> response = handleHttp(headerList,
          payload_SignedEncrypted, OAUTH_URL_UAT);
      HttpStatus statusCode = (HttpStatus) response.get("STATUS");

      if (statusCode == HttpStatus.OK) {
        return new String((byte[]) response.get("BODY"));
      } else { // error msg received instead of expected statement
        String errorMsg = (String) response.get("BODY");
        Logger.getLogger(Handler.class.getName())
            .log(Level.SEVERE, null, errorMsg);
        throw new HandlerException(errorMsg);
      }
    } catch (IOException | CertificateException | UnrecoverableKeyException |
        NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Parsing response to show error or valid message logic.
   *
   * @param responseDoc document to be parsed.
   * @param type "" for TYPE_AUTH or "BASE64" for TYPE_PAY_INIT.
   * @param tagName differentiate between response handling logic: use
   *        "//access_token/text()" for Authentication & "//Response/text()"
   *        for Payment Initiation.
   * @return response message.
   * @throws HandlerException custom exception for Handler class.
   */
  public static String parseAuthOrPayInitResponse (Document responseDoc, String type,
      String tagName) throws HandlerException, XPathExpressionException {

    XPath xpath = XPathFactory.newInstance().newXPath();

    String errorInResponse = "";
    Element docRoot = responseDoc.getDocumentElement();
    if (docRoot == null || docRoot.getNodeName() == null) {
      errorInResponse = "Response Message Doesn't have expected Information";
    } else {
      if (docRoot.getNodeName().equalsIgnoreCase("errormessage")) {
        StringBuffer errorReponseSB = new StringBuffer();

        String httpCodeTag = null, httpMessage = null, moreInformation = null;

        try {
          NodeList nodes = (NodeList) xpath.compile("//httpCode/text()")
              .evaluate(responseDoc, XPathConstants.NODESET);
          if (nodes != null && nodes.getLength() == 1) {
            httpCodeTag = "HTTP:" + nodes.item(0).getNodeValue();
          }
          NodeList httpMessageNodes = (NodeList) xpath
              .compile("//httpMessage/text()")
              .evaluate(responseDoc, XPathConstants.NODESET);
          if (httpMessageNodes != null && httpMessageNodes.getLength() == 1) {
            httpMessage =
                "HTTP:" + httpMessageNodes.item(0).getNodeValue();
          }

          NodeList moreInformationNodes = (NodeList) xpath
              .compile("//httpMessage/text()")
              .evaluate(responseDoc, XPathConstants.NODESET);
          if (moreInformationNodes != null
              && moreInformationNodes.getLength() == 1) {
            moreInformation =
                "HTTP:" + moreInformationNodes.item(0).getNodeValue();
          }
        } catch (XPathExpressionException e) {
          Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
          throw new HandlerException(e.getMessage());
        }

        errorReponseSB.append(httpCodeTag).append(": ")
            .append(httpMessage)
            .append(": ").append(moreInformation);
        errorInResponse = errorReponseSB.toString();
      }
    }
    if (errorInResponse.trim().length() > 0) {
      throw new HandlerException(errorInResponse);
    } else {
      NodeList nodes = (NodeList) xpath.compile(tagName)
          .evaluate(responseDoc, XPathConstants.NODESET);
      if (nodes != null && nodes.getLength() == 1) {
        String response = nodes.item(0).getNodeValue();

        if ("BASE64".equals(type)) {
          return new String(Base64.decodeBase64(response));
        } else {
          return response;
        }
      } else {
        throw new HandlerException("No content extracted from response");
      }
    }
  }

  /**
   * Create a document class instance based on pain.001.001.03 format.
   *
   * @return pain format document object.
   * @throws DatatypeConfigurationException if an unexpected event happens when
   *                                        creating datatype instances.
   */
  public static deskera.fintech.pain001.Document createPayInitDocumentInstance()
      throws DatatypeConfigurationException {
    DatatypeFactory dataType = DatatypeFactory.newInstance();

    /* Start of Document */
    deskera.fintech.pain001.Document document =
        new deskera.fintech.pain001.Document();
    /* Start of cstmrCdtTrfInitn */
    CustomerCreditTransferInitiationV03 cstmrCdtTrfInitn =
        new CustomerCreditTransferInitiationV03();
    /* Start of GrpHdr */
    GroupHeader32 grpHdr = new GroupHeader32();
    grpHdr.setMsgId("GBP161111000001");
    XMLGregorianCalendar creDtTm =
        dataType.newXMLGregorianCalendar(2016,11,11,3, 51, 15, 0, 0);
    creDtTm.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
    creDtTm.setTimezone(DatatypeConstants.FIELD_UNDEFINED);
    grpHdr.setCreDtTm(creDtTm);
    grpHdr.setNbOfTxs("1");
    grpHdr.setCtrlSum(new BigDecimal("1.00"));
    PartyIdentification32 initgPty = new PartyIdentification32();
    initgPty.setNm("ABC");
    grpHdr.setInitgPty(initgPty);
    cstmrCdtTrfInitn.setGrpHdr(grpHdr);
    /* End of GrpHdr */
    /* Start of PmtInf */
    List<PaymentInstructionInformation3> pmtInfList = cstmrCdtTrfInitn.getPmtInf();
    PaymentInstructionInformation3 pmtInf = new PaymentInstructionInformation3();
    pmtInfList.add(pmtInf);
    pmtInf.setPmtInfId("98765432 Fund Transfer Domestic");
    pmtInf.setPmtMtd(PaymentMethod3Code.TRF);
    pmtInf.setNbOfTxs("1");
    pmtInf.setCtrlSum(new BigDecimal("1.00"));
    PaymentTypeInformation19 pmtTpInf = new PaymentTypeInformation19();
    ServiceLevel8Choice svcLvl = new ServiceLevel8Choice();
    svcLvl.setCd("URGP");
    pmtTpInf.setSvcLvl(svcLvl);
    pmtInf.setPmtTpInf(pmtTpInf);
    XMLGregorianCalendar reqdExctnDt =
        dataType.newXMLGregorianCalendarDate(2016,11,16, 0);
    reqdExctnDt.setTimezone(DatatypeConstants.FIELD_UNDEFINED);
    pmtInf.setReqdExctnDt(reqdExctnDt);
    /* Start of Dbtr */
    PartyIdentification32 dbtr = new PartyIdentification32();
    dbtr.setNm("ABCD DEMO");
    PostalAddress6 pstlAdr1 = new PostalAddress6();
    pstlAdr1.setCtry("GB");
    dbtr.setPstlAdr(pstlAdr1);
    Party6Choice id1 = new Party6Choice();
    OrganisationIdentification4 orgId = new OrganisationIdentification4();
    orgId.setBICOrBEI("CITIGB2L");
    id1.setOrgId(orgId);
    dbtr.setId(id1);
    pmtInf.setDbtr(dbtr);
    /* End of Dbtr */
    /* Start of DbtrAcct */
    CashAccount16 dbtrAcct = new CashAccount16();
    AccountIdentification4Choice id2 = new AccountIdentification4Choice();
    GenericAccountIdentification1 othr1 = new GenericAccountIdentification1();
    othr1.setId("12345678");
    id2.setOthr(othr1);
    dbtrAcct.setId(id2);
    dbtrAcct.setCcy("USD");
    pmtInf.setDbtrAcct(dbtrAcct);
    /* End of DbtrAcct */
    /* Start of DbtrAgt */
    BranchAndFinancialInstitutionIdentification4 dbtrAgt1 =
        new BranchAndFinancialInstitutionIdentification4();
    FinancialInstitutionIdentification7 finInstnId =
        new FinancialInstitutionIdentification7();
    finInstnId.setBIC("CITIGB2L");
    PostalAddress6 pstlAdr2 = new PostalAddress6();
    pstlAdr2.setCtry("GB");
    finInstnId.setPstlAdr(pstlAdr2);
    dbtrAgt1.setFinInstnId(finInstnId);
    pmtInf.setDbtrAgt(dbtrAgt1);
    /* End of DbtrAgt */
    pmtInf.setChrgBr(ChargeBearerType1Code.DEBT);
    /* Start of cdtTrfTxInf */
    List<CreditTransferTransactionInformation10> cdtTrfTxInfList =
        pmtInf.getCdtTrfTxInf();
    CreditTransferTransactionInformation10 cdtTrfTxInf =
        new CreditTransferTransactionInformation10();
    /* Start of PmtId */
    PaymentIdentification1 pmtId = new PaymentIdentification1();
    pmtId.setEndToEndId("ABC1234");
    cdtTrfTxInf.setPmtId(pmtId);
    /* End of PmtId */
    /* Start of Amt */
    AmountType3Choice amt = new AmountType3Choice();
    ActiveOrHistoricCurrencyAndAmount instdAmt =
        new ActiveOrHistoricCurrencyAndAmount();
    instdAmt.setCcy("USD");
    instdAmt.setValue(new BigDecimal("1.00"));
    amt.setInstdAmt(instdAmt);
    cdtTrfTxInf.setAmt(amt);
    /* Start of UltmtDbtr */
    PartyIdentification32 ultmtDbtr = new PartyIdentification32();
    Party6Choice id3 = new Party6Choice();
    PersonIdentification5 prvtId = new PersonIdentification5();
    List<GenericPersonIdentification1> othrList = prvtId.getOthr();
    GenericPersonIdentification1 othr = new GenericPersonIdentification1();
    othr.setId("ABCDEF UK BR600 012345");
    PersonIdentificationSchemeName1Choice schmeNm =
        new PersonIdentificationSchemeName1Choice();
    schmeNm.setPrtry("INST");
    othr.setSchmeNm(schmeNm);
    othrList.add(othr);
    id3.setPrvtId(prvtId);
    ultmtDbtr.setId(id3);
    cdtTrfTxInf.setUltmtDbtr(ultmtDbtr);
    /* End of UltmtDbtr */
    /* Start of CdtrAgt */
    BranchAndFinancialInstitutionIdentification4 cdtrAgt2 =
        new BranchAndFinancialInstitutionIdentification4();
    FinancialInstitutionIdentification7 finInstnId2 =
        new FinancialInstitutionIdentification7();
    finInstnId2.setBIC("CITIGB2L");
    ClearingSystemMemberIdentification2 clrSysMmbId =
        new ClearingSystemMemberIdentification2();
    clrSysMmbId.setMmbId("185008");
    finInstnId2.setClrSysMmbId(clrSysMmbId);
    finInstnId2.setNm("CITIBANK(ISO)");
    PostalAddress6 pstlAdr3 = new PostalAddress6();
    pstlAdr3.setCtry("GB");
    finInstnId2.setPstlAdr(pstlAdr3);
    cdtrAgt2.setFinInstnId(finInstnId2);
    cdtTrfTxInf.setCdtrAgt(cdtrAgt2);
    /* End of CdtrAgt */
    /* Start of Cdtr */
    PartyIdentification32 cdtr = new PartyIdentification32();
    cdtr.setNm("8010643122X XXXXXXXXXXXXX XXX");
    PostalAddress6 pstlAdr4 = new PostalAddress6();
    pstlAdr4.setCtry("GB");
    cdtr.setPstlAdr(pstlAdr4);
    ContactDetails2 ctctDtls = new ContactDetails2();
    ctctDtls.setNm("ABC LIMITED");
    cdtr.setCtctDtls(ctctDtls);
    cdtTrfTxInf.setCdtr(cdtr);
    /* End of Cdtr */
    /* Start of CdtrAcct */
    CashAccount16 cdtrAcct = new CashAccount16();
    AccountIdentification4Choice id4 = new AccountIdentification4Choice();
    id4.setIBAN("GB27CITI18500812345678");
    cdtrAcct.setId(id4);
    cdtTrfTxInf.setCdtrAcct(cdtrAcct);
    /* End of CdtrAcct */
    /* Start of RmtInf */
    RemittanceInformation5 rmtInf = new RemittanceInformation5();
    List<String> ustrdList = rmtInf.getUstrd();
    ustrdList.add("TR002638");
    cdtTrfTxInf.setRmtInf(rmtInf);
    /* End of RmtInf */
    cdtTrfTxInfList.add(cdtTrfTxInf);
    /* End of cdtTrfTxInf */
    /* End of PmtInf */
    /* End of cstmrCdtTrfInitn */
    document.setCstmrCdtTrfInitn(cstmrCdtTrfInitn);
    /* End of Document */

    return document;
  }

  /**
   * Create ISOXML payload used for payment initiation API calling.
   *
   * @return XML String formatted in pain.001.001.03
   * @throws HandlerException custom exception for Handler class will trigger
   *                          if any unexpected event happened when creating
   *                          the XML payload String.
   */
  public static String createPayInitPayload() throws HandlerException {
    try {
      deskera.fintech.pain001.Document document = createPayInitDocumentInstance();
      JAXBElement<deskera.fintech.pain001.Document> documentElement =
          (new ObjectFactory()).createDocument(document);
      BankFormatConverter<deskera.fintech.pain001.Document> convertor =
          new BankFormatConverter<>(PAIN001_CLASS_PATH);
      return convertor.writeElementToXML(documentElement);
    } catch (BankFormatConverterException | DatatypeConfigurationException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Payment Initiation API: Generate Base64 request payload from ISO XML Payload.
   *
   * @param isoPayInXML input xml string.
   * @return base64 string generated from {@code isoPayInXML} placed in
   *         <Request><paymentBase64> tag.
   * @throws HandlerException a custom exception for Handler class is triggered
   *                          when the input is not of the correct ISO XML form
   *                          or unexpected event occurred during XML parsing.
   */
  public static String generateBase64PayloadFromISOXML (String isoPayInXML)
      throws HandlerException {

    if(isoPayInXML.trim().equals("")) {
      String message = "Fatal: Non-ISO format string received";
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, message);
      throw new HandlerException(message);
    }

    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document doc = builder.parse(
          new ByteArrayInputStream(isoPayInXML.getBytes(StandardCharsets.UTF_8)));
      Element root = doc.getDocumentElement();
      String nameSpace = root.getNamespaceURI();

      if (nameSpace == null || !nameSpace.equals(OUTGOING_PAYMENT_TYPE)) {
        String message = "Fatal: Non-ISO format string received";
        Logger.getLogger(Handler.class.getName())
            .log(Level.SEVERE, null, message);
        throw new HandlerException(message);
      }
    } catch (ParserConfigurationException | IOException | SAXException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }

    StringBuffer xmlStrSb = new StringBuffer();
    final char pem_array[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
        'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
        'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', '+', '/'
    };
    byte inBuff[] = isoPayInXML.getBytes();
    int numBytes = inBuff.length;
    if (numBytes == 0)
      return "";
    byte outBuff[] = new byte[(numBytes - 1) / 3 + 1 << 2];
    int pos = 0;
    int len = 3;
    for (int j = 0; j < numBytes; j += 3) {
      if (j + 3 > numBytes)
        len = numBytes - j;
      if (len == 3) {
        byte a = inBuff[j];
        byte b = inBuff[j + 1];
        byte c = inBuff[j + 2];
        outBuff[pos++] = (byte) pem_array[a >>> 2 & 0x3f];
        outBuff[pos++] = (byte) pem_array[(a << 4 & 0x30) + (b >>> 4 & 0xf)];
        outBuff[pos++] = (byte) pem_array[(b << 2 & 0x3c) + (c >>> 6 & 3)];
        outBuff[pos++] = (byte) pem_array[c & 0x3f];
      } else if (len == 2) {
        byte a = inBuff[j];
        byte b = inBuff[j + 1];
        byte c = 0;
        outBuff[pos++] = (byte) pem_array[a >>> 2 & 0x3f];
        outBuff[pos++] = (byte) pem_array[(a << 4 & 0x30) + (b >>> 4 & 0xf)];
        outBuff[pos++] = (byte) pem_array[(b << 2 & 0x3c) + (c >>> 6 & 3)];
        outBuff[pos++] = 61;
      } else {
        byte a = inBuff[j];
        byte b = 0;
        outBuff[pos++] = (byte) pem_array[a >>> 2 & 0x3f];
        outBuff[pos++] = (byte) pem_array[(a << 4 & 0x30) + (b >>> 4 & 0xf)];
        outBuff[pos++] = 61;
        outBuff[pos++] = 61;
      }
    }
    String paymentBase64 = new String(outBuff);
    xmlStrSb.append("<Request>");
    xmlStrSb.append("<paymentBase64>");
    xmlStrSb.append(paymentBase64);
    xmlStrSb.append("</paymentBase64>");
    xmlStrSb.append("</Request>");
    return xmlStrSb.toString();
  }

  /**
   * Payment initiation logic via Outgoing Payment method, which takes the
   * necessary data required in ISOXML V3 (pain.001.001.03)
   *
   * @param ISOXML data in ISOXML V3 format.
   * @return a response that denotes whether the payment has passed the basic
   *         validations. The Partner has the ability to view transaction or
   *         payment status at any later point using the Payment Status Inquiry
   *         API.
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload.
   * @throws HandlerException custom exception for Handler class.
   */
  public byte[] initiatePayment (String ISOXML) throws XMLSecurityException,
      HandlerException {
    String base64Payload = generateBase64PayloadFromISOXML(ISOXML);
    String payload_SignedEncrypted = signAndEncryptXMLForCiti(base64Payload);
    Map<String, String> headerList = new HashMap<>();
    headerList.put("Content-Type", "application/xml");
    headerList.put(PAYMENT_TYPE_HEADER, OUTGOING_PAYMENT_TYPE);
    headerList.put(HttpHeaders.AUTHORIZATION, "Bearer " + oAuthToken);
    HashMap<String, Object> response = handleHttp(headerList,
        payload_SignedEncrypted, PAY_INIT_URL_UAT + "client_id=" + getClientId());
    HttpStatus statusCode = (HttpStatus) response.get("STATUS");

    if (statusCode == HttpStatus.OK) {
      return (byte[]) response.get("BODY");
    } else { // error msg received instead of expected statement
      String errorMsg = (String) response.get("BODY");
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, errorMsg);
      throw new HandlerException(errorMsg);
    }
  }

  /**
   * Balance inquiry logic.
   *
   * @param payload Payload that contains account number or branch number
   * @return a response in camt.052.001.02
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload.
   * @throws HandlerException custom exception for Handler class.
   */
  public byte[] checkBalance (String payload) throws XMLSecurityException,
      HandlerException {
    String payload_SignedEncrypted = signAndEncryptXMLForCiti(payload);
    Map<String, String> headerList = new HashMap<>();
    headerList.put("Content-Type", "application/xml");
    headerList.put(HttpHeaders.AUTHORIZATION, "Bearer " + oAuthToken);
    HashMap<String, Object> response = handleHttp(
        headerList, payload_SignedEncrypted,
        BALANCE_INQUIRY_URL_UAT + "client_id=" + getClientId());
    HttpStatus statusCode = (HttpStatus) response.get("STATUS");

    if (statusCode == HttpStatus.OK) {
      return (byte[]) response.get("BODY");
    } else { // error msg received instead of expected statement
      String errorMsg = (String) response.get("BODY");
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, errorMsg);
      throw new HandlerException(errorMsg);
    }
  }

  /**
   * Statement initiation logic.
   *
   * @param payLoad data in XML format.
   * @return a response that contains the statement ID which can be used to call
   *         statement retrieval API to obtain the specific statement file.
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload.
   * @throws HandlerException custom exception for Handler class.
   */
  public byte[] initiateStatement (String payLoad) throws XMLSecurityException,
      HandlerException {
    String payload_SignedEncrypted = signAndEncryptXMLForCiti(payLoad);
    Map<String, String> headerList = new HashMap<>();
    headerList.put("Content-Type", "application/xml");
    headerList.put(HttpHeaders.AUTHORIZATION, "Bearer " + oAuthToken);
    HashMap<String, Object> response = handleHttp(headerList,
        payload_SignedEncrypted, STATEMENT_INIT_URL_UAT + "client_id=" + getClientId());
    HttpStatus statusCode = (HttpStatus) response.get("STATUS");

    if (statusCode == HttpStatus.OK) {
      return (byte[]) response.get("BODY");
    } else { // error msg received instead of expected statement
      String errorMsg = (String) response.get("BODY");
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, errorMsg);
      throw new HandlerException(errorMsg);
    }
  }

  /**
   * parsing logic to extract only the statement id from the statement initiation
   * response after the latter is decrypted and verified by the client.
   *
   * @param XML the decrypted and verified statement initiation response.
   * @return the attached decryption key used to decrypt the statement file.
   * @throws HandlerException if an unexpected event occurs when taking out the
   *                          statement id from the {@code XML}.
   */
  public static String extractStatementId (String XML)
      throws HandlerException {
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document document = builder.parse(new InputSource(new StringReader(XML)));
      Element rootElement = document.getDocumentElement();
      NodeList statementIdElement = rootElement.getElementsByTagName("statementId");
      if (statementIdElement != null && statementIdElement.getLength() > 0) {
        NodeList subList = statementIdElement.item(0).getChildNodes();

        if (subList != null && subList.getLength() > 0) {
          return subList.item(0).getNodeValue();
        }
      }

      throw new HandlerException("Fail to extract statement id from XML");
    } catch (ParserConfigurationException | IOException | SAXException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Parse MIME response into 2 parts: 1. encrypted and signed decryption key
   * and 2. encrypted statement file.
   *
   * @param XMLResponse a MIME response which has 2 parts. First part is of XML
   *                    encrypted which has to be decrypted and VerifySigned to
   *                    get a plain XML response. The plain response has an
   *                    AttachmentDecryptionKey and is used to decrypt the Binary
   *                    Statement (2nd part of MIME) which is the expected
   *                    Statement file.
   *
   *                    The second part contains the Statement File attached in
   *                    MTOM format which follows SWIFT MT940, or ISO XML
   *                    camt.053.001.02 or SWIFT MT942 or ISO XML camt.052.001.02
   *                    standards. If the file size exceeds 4 MB, then there will
   *                    be an error message in response will be sent back to the
   *                    partner.
   *
   *                    If the request is rejected due to validation errors or
   *                    data issues, the response follows a custom XML format.
   * @return a HashMap that contains the encrypted decryption key from the xml
   *         part of {@code response}, which is used to decrypt the encrypted
   *         statement file from the second part of {@code response}.
   * @throws HandlerException custom exception for Handler class.
   */
  public static HashMap<String, Object> parseMIMEResponse (byte[] XMLResponse)
      throws HandlerException{
    try {
      String responseStatRetXMLStr = "";
      byte[] encryptedStatByteArray = null;
      /* need to import javax.activation.DataSource for this below */
      MimeMultipart mp = new MimeMultipart(
          new ByteArrayDataSource(XMLResponse, TEXT_XML_VALUE));
      for (int i = 0; i < mp.getCount(); i++) {
        BodyPart bodyPart = mp.getBodyPart(i);
        String contentType = bodyPart.getContentType();
        Logger.getLogger(Handler.class.getName())
            .info("ContentType==>" + contentType);
        Logger.getLogger(Handler.class.getName())
            .info("Content==>" + bodyPart.getContent());

        if (bodyPart.isMimeType("text/xml") ||
            bodyPart.isMimeType("application/xml")) {
          if (SharedByteArrayInputStream.class
              .equals(bodyPart.getContent().getClass())) {
            responseStatRetXMLStr = IOUtils.toString((SharedByteArrayInputStream)
                    bodyPart.getContent(), StandardCharsets.UTF_8);
          } else {
            responseStatRetXMLStr = (String) bodyPart.getContent();
          }
        } else { //if application/octet-stream or application/xop+xml
          if (String.class.equals(bodyPart.getContent().getClass())) {
            encryptedStatByteArray = ((String) bodyPart.getContent()).getBytes();
          } else {
            ByteArrayInputStream bais =
                (ByteArrayInputStream) bodyPart.getContent();
            encryptedStatByteArray = toByteArray(bais);
          }
        }
      }

      if (responseStatRetXMLStr.isEmpty() || encryptedStatByteArray == null)
        throw new HandlerException("Fail to parse the MIME response into 2 parts");

      HashMap<String, Object> result = new HashMap<>();
      result.put("ENCRYPTED_KEY", responseStatRetXMLStr);
      result.put("ENCRYPTED_FILE", encryptedStatByteArray);
      return result;

    } catch (MessagingException | IOException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Decrypt the encrypted attachment (excluding its first 8 bytes) using the
   * decryption key and IvParameterSpec instance from the xml section of MIME
   * response.
   *
   * @param decryptionKey the decryption key.
   * @param input encrypted attachment (including first 8 bytes).
   * @return decrypted statement file.
   * @throws HandlerException custom exception for Handler class.
   */
  public static byte[] des3DecodeCBC (String decryptionKey, byte[] input)
      throws HandlerException {
    try {
      // attachment byte array from MIME response
      int ivLen = 8;
      byte[] keyiv = new byte[ivLen];
      System.arraycopy(input, 0, keyiv, 0, ivLen);

      int dataLen = input.length - ivLen;
      byte[] data = new byte[dataLen];
      System.arraycopy(input, ivLen, data, 0, dataLen);

      DESedeKeySpec spec = new DESedeKeySpec(Base64.decodeBase64(decryptionKey));
      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
      Key desKey = keyFactory.generateSecret(spec);

      Cipher cipher = Cipher.getInstance("TripleDES/CBC/NoPadding");
      IvParameterSpec ips = new IvParameterSpec(keyiv);
      cipher.init(Cipher.DECRYPT_MODE, desKey, ips);

      byte[] bout = cipher.doFinal(data);

      return Base64.decodeBase64(bout);
    } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException |
        InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException
        | InvalidAlgorithmParameterException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * parsing logic to extract only the attachment decryption key value from the
   * first section of the statement retrieval response after the latter is
   * decrypted and verified by the client.
   *
   * @param XML the decrypted first section of statement retrieval response.
   * @return the attached decryption key used to decrypt the statement file.
   * @throws HandlerException if an unexpected event occurs when taking out the
   *                          attachmentDecryptionKey value from the {@code XML}
   *                          string.
   */
  public static String extractAttachmentDecryptionKey (String XML)
      throws HandlerException {
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document document = builder.parse(new InputSource(new StringReader(XML)));
      Element rootElement = document.getDocumentElement();
      NodeList decryptionKeyElement = rootElement.getElementsByTagName("ns2:attachmentDecryptionKey");
      if (decryptionKeyElement != null && decryptionKeyElement.getLength() > 0) {
        NodeList subList = decryptionKeyElement.item(0).getChildNodes();

        if (subList != null && subList.getLength() > 0) {
          return subList.item(0).getNodeValue();
        }
      }

      throw new HandlerException("Fail to extract attachment decryption key from XML");
    } catch (ParserConfigurationException | IOException | SAXException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Get the intended statement file using its statement ID.
   *
   * @param payload the xml payload that contains statement ID.
   * @param url the address that we are sending the statement retrieval request
   *            to.
   * @return the expected statement file decrypted.
   * @throws XMLSecurityException if an unexpected exception occurs while
   *                              decrypting the xml section of the body.
   * @throws CertificateEncodingException if an unexpected exception occurs while
   *                                      verifying the xml section of the body.
   * @throws HandlerException if an unexpected exception occurs while requesting
   *                          for the specific statement file from the server.
   */
  public byte[] retrieveStatement (String payload, String url) throws XMLSecurityException,
      CertificateEncodingException, HandlerException {

    String payload_SignedEncrypted = signAndEncryptXMLForCiti(payload);
    Map<String, String> headerList = new HashMap<>();
    headerList.put("Content-Type", "application/xml");
    headerList.put(HttpHeaders.AUTHORIZATION, "Bearer " + oAuthToken);
    HashMap<String, Object> response = handleHttp(headerList,
        payload_SignedEncrypted, url + "client_id=" + getClientId());
    HttpStatus statusCode = (HttpStatus) response.get("STATUS");

    if (statusCode == HttpStatus.OK) {
      HashMap<String, Object> body =
          parseMIMEResponse((byte[]) response.get("BODY"));
      String firstHalf =
          decryptAndVerifyXMLFromCiti((String) body.get("ENCRYPTED_KEY"));
      String decryptionKey = extractAttachmentDecryptionKey(firstHalf);
      return des3DecodeCBC(decryptionKey, (byte[]) body.get("ENCRYPTED_FILE"));
    } else { // error msg received instead of expected statement
      String errorMsg = (String) response.get("BODY");
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, errorMsg);
      throw new HandlerException(errorMsg);
    }
  }

  /**
   * Converter from camt.053.001.02 formatted String to its corresponding json
   * String.
   *
   * @param CAMT053Str XML string in ISO 20022 camt.053.001.02 format.
   * @return its corresponding json format string.
   * @throws HandlerException if an unexpected event occurs during the conversion
   *                          process from XML String to JAXBElement and then to
   *                          json String.
   */
  public static String readCAMT053ToJson(String CAMT053Str) throws HandlerException {
    try {
      BankFormatConverter<deskera.fintech.camt053.Document>
          converter = new BankFormatConverter<>(CAMT053_CLASS_PATH);
      JAXBElement<deskera.fintech.camt053.Document> documentElement =
          converter.readXMLToElement(CAMT053Str);
      return converter.writeElementToJson(documentElement);
    } catch (BankFormatConverterException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Converter from camt.052.001.02 formatted String to its corresponding json
   * String.
   *
   * @param CAMT052Str XML string in ISO 20022 camt.052.001.02 format.
   * @return its corresponding json format string.
   * @throws HandlerException if an unexpected event occurs during the conversion
   *                          process from XML String to JAXBElement and then to
   *                          json String.
   */
  public static String readCAMT052ToJson(String CAMT052Str) throws HandlerException {
    try {
      BankFormatConverter<deskera.fintech.camt052.Document>
          converter = new BankFormatConverter<>(CAMT052_CLASS_PATH);
      JAXBElement<deskera.fintech.camt052.Document> documentElement =
          converter.readXMLToElement(CAMT052Str);
      return converter.writeElementToJson(documentElement);
    } catch (BankFormatConverterException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

//  // TODO: check if we need these.
//  /**
//   * Load Keystore file that has all certs.
//   *
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public void loadKeystoreWithAllCerts () throws HandlerException {
//    try {
//      FileInputStream fis = new FileInputStream(KEYSTORE_FILEPATH);
//      ks.load(fis, KEYSTORE_PASSWORD.toCharArray());
//      fis.close();
//    } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//  /**
//   * Getting the XML Payload as Document object.
//   *
//   * @return converted document.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public Document getXMLResponsePayloadAsDoc (String responseXMLPayload) throws HandlerException {
//    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
//    factory.setNamespaceAware(true);
//    try {
//      DocumentBuilder builder = factory.newDocumentBuilder();
//      return builder.parse(new InputSource(new StringReader(responseXMLPayload)));
//    } catch (ParserConfigurationException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    } catch (SAXException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    } catch (IOException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//   * Getting public client decryption key.
//   *
//   * @return public client decryption key.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public X509Certificate getClientPublicDecrytionKey () throws HandlerException {
//    try {
//      X509Certificate decryptCert = (X509Certificate) ks
//          .getCertificate(HandlerConstant.clientDecryptKeyAlias);
//      decryptCert.checkValidity();
//      return decryptCert;
//    } catch (CertificateExpiredException | CertificateNotYetValidException |
//        KeyStoreException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//  /**
//   * Getting private client decryption key.
//   *
//   * @return private client decryption key.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public PrivateKey getClientPrivateDecryptionKey () throws HandlerException {
//    try {
//      return (PrivateKey) ks.getKey(HandlerConstant.clientDecryptKeyAlias,
//              KEYSTORE_PASSWORD.toCharArray());
//    } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//  /**
//   * Decrypt statement file.
//   *
//   * @param encryptedStatementFile byteArray of encrypted statement file.
//   * @return decrypted statement file as byteArray.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public static byte[] decryptStatementFile (byte[] encryptedStatementFile)
//      throws HandlerException {
//
//    String decryptionKey = "";
//    NodeList nodes = evalFromString(
//        "//statementRetrievalResponse//attachmentDecryptionKey",
//        decryptedStatementRetrievalResponse);
//    int len = (nodes != null) ? nodes.getLength() : 0;
//    if (len == 1) {
//      decryptionKey = nodes.item(0).getTextContent();
//    }
//    int ivLen = 8;
//    byte[] keyiv = new byte[ivLen];
//    System.arraycopy(encryptedStatementFile, 0, keyiv, 0, ivLen);
//    int dataLen = encryptedStatementFile.length - ivLen;
//    byte[] data = new byte[dataLen];
//    System.arraycopy(encryptedStatementFile, ivLen, data, 0, dataLen);
//
//    try {
//      DESedeKeySpec spec = new DESedeKeySpec(
//          Base64.decodeBase64(decryptionKey));
//      SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
//      Key deskey = keyfactory.generateSecret(spec);
//      Cipher cipher = Cipher
//          .getInstance("TripleDES/CBC/NoPadding");//PKCS5Padding NoPadding
//      IvParameterSpec ips = new IvParameterSpec(keyiv);
//      cipher.init(Cipher.DECRYPT_MODE, deskey, ips);
//      byte[] bout = cipher.doFinal(data);
//      return Base64.decodeBase64(bout);
//    } catch (NoSuchAlgorithmException | InvalidKeyException |
//        NoSuchPaddingException | InvalidAlgorithmParameterException |
//        InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//  /**
//   * Parsing MTOM Response (Parser for Statement Retrieval Response).
//   *
//   * @param response MTOM response.
//   * @return response in byteArray.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public static byte[] parseMTOMResponse (String response)
//      throws HandlerException {
//    try {
//      MimeMultipart mp = new MimeMultipart(
//          new ByteArrayDataSource(response, MediaType.TEXT_XML));
//      for (int i = 0; i < mp.getCount(); i++) {
//        BodyPart bodyPart = mp.getBodyPart(i);
//        String contentType = bodyPart.getContentType();
//        Logger.getLogger(Handler.class.getName()).info("ContentType==>" + contentType);
//        if (bodyPart.isMimeType("text/xml")) {// if text/xml
//          responseStatRetXMLStr = (String) bodyPart.getContent();
//        } else {
//          ByteArrayInputStream bais = (ByteArrayInputStream) bodyPart
//              .getContent();
//          ByteArrayOutputStream buffer = new ByteArrayOutputStream();
//          int nRead;
//          byte[] data = new byte[1024];
//          while ((nRead = bais.read(data, 0, data.length)) != -1) {
//            buffer.write(data, 0, nRead);
//          }
//          buffer.flush();
//          return buffer.toByteArray();
//        }
//      }
//    } catch (MessagingException | IOException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//  /**
//   * Payment initiation logic.
//   *
//   * @return response that contains the wanted statement ID(s).
//   * @throws XMLSecurityException if an unexpected exception occurs while signing
//   *                              the auth payload or encrypting the payload.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public String initialisePayment (String payInitPayload)
//      throws XMLSecurityException, HandlerException {
//    try {
//      KeyStore clientStore = KeyStore.getInstance("PKCS12");
//      clientStore.load(new FileInputStream(DESKERA_SSL_CERT_FILE_PATH),
//          DESKERA_SSL_CERT_PWD.toCharArray());
//      KeyManagerFactory kmf = KeyManagerFactory
//          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
//      kmf.init(clientStore, DESKERA_SSL_CERT_PWD.toCharArray());
//      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
//      sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
//      HttpsURLConnection
//          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());
//      Client client = new Client(new URLConnectionClientHandler(
//          new HttpURLConnectionFactory() {
//            Proxy proxy = null;
//
//            public HttpURLConnection getHttpURLConnection(URL url)
//                throws IOException {
//              if (proxy == null && !HandlerConstant.PROXY_URL.isEmpty()) {
//                proxy = new Proxy(Proxy.Type.HTTP,
//                    new InetSocketAddress(HandlerConstant.PROXY_URL, 8080));
//              } else {
//                proxy = Proxy.NO_PROXY;
//              }
//              return (HttpURLConnection) url.openConnection(proxy);
//            }
//          }), new DefaultClientConfig());
//      WebResource webResource = client.resource(HandlerConstant.PAY_INIT_URL_UAT)
//          .queryParam("client_id", getClientId());
//      Builder builder = webResource.type(MediaType.APPLICATION_XML);
//      builder.header(HttpHeaders.AUTHORIZATION,
//          "Bearer " + oAuthToken);
//      builder.header("payloadType",
//          "urn:iso:std:iso:20022:tech:xsd:pain.001.001.03");
//      String payInitPayload_SignedEncrypted =
//          signAndEncryptXMLForCiti(payInitPayload);
//      ClientResponse clientResponse = builder
//          .post(ClientResponse.class, payInitPayload_SignedEncrypted);
//      return clientResponse.getEntity(String.class);
//    } catch (IOException | CertificateException | UnrecoverableKeyException |
//        NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//
//  /**
//   * Balance inquiry logic.
//   *
//   * @param balanceInquiryPayload request body in xml.
//   * @return response xml that contains the balance value, which follow ISO20022
//   *         v2 (camt.052.001.02) standards.
//   * @throws XMLSecurityException if an unexpected exception occurs while signing
//   *                              the auth payload or encrypting the payload.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public String checkBalance (String balanceInquiryPayload)
//      throws XMLSecurityException, HandlerException {
//
////    try {
////      KeyStore clientStore = KeyStore.getInstance("PKCS12");
////      clientStore.load(new FileInputStream(DESKERA_SSL_CERT_FILE_PATH),
////              DESKERA_SSL_CERT_PWD.toCharArray());
////      KeyManagerFactory kmf = KeyManagerFactory
////          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
////      kmf.init(clientStore, DESKERA_SSL_CERT_PWD.toCharArray());
////      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
////      sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
////      HttpsURLConnection
////          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());
//    Client client = new Client(new URLConnectionClientHandler(
//        new HttpURLConnectionFactory() {
//          Proxy proxy = null;
//
//          public HttpURLConnection getHttpURLConnection(URL url)
//              throws IOException {
//            if (proxy == null && !HandlerConstant.PROXY_URL.isEmpty()) {
//              proxy = new Proxy(Proxy.Type.HTTP,
//                  new InetSocketAddress(HandlerConstant.PROXY_URL, 8080));
//            } else {
//              proxy = Proxy.NO_PROXY;
//            }
//            return (HttpURLConnection) url.openConnection(proxy);
//          }
//        }), new DefaultClientConfig());
//    WebResource webResource = client.resource(BALANCE_INQUIRY_URL_UAT)
//        .queryParam("client_id", getClientId());
//    Builder builder = webResource.accept(MediaType.APPLICATION_XML);
//    builder.header("Content-Type", "application/xml");
//    builder.header(HttpHeaders.AUTHORIZATION,"Bearer " + oAuthToken);
//    String balanceInquiryPayload_SignedEncrypted = signAndEncryptXMLForCiti(
//        balanceInquiryPayload);
//    ClientResponse clientResponse = builder.post(ClientResponse.class,
//        balanceInquiryPayload_SignedEncrypted);
//    return clientResponse.getEntity(String.class);
////    } catch (IOException | CertificateException | NoSuchAlgorithmException |
////        UnrecoverableKeyException | KeyStoreException | KeyManagementException e) {
////      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
////      throw new HandlerException(e.getMessage());
////    }
//  }
//
//  /**
//   * Statement retrieval logic using statement ID as part of request body.
//   *
//   * @param requestStatementPayload request body in xml.
//   * @return a MIME response which has 2 parts. First part is of XML encrypted
//   *         which has to be decrypted and VerifySigned to get a plain XML
//   *         response. The plain response has an AttachmentDecryptionKey and is
//   *         used to decrypt the Binary Statement (2nd part of MIME) which is the
//   *         expected Statement file.
//   *
//   *         The second part contains the Statement File attached in MTOM format
//   *         which follows SWIFT MT940, or ISO XML camt.053.001.02 or SWIFT MT942
//   *         or ISO XML camt.052.001.02 standards. If the file size exceeds 4 MB,
//   *         then there will be an error message in response will be sent back
//   *         to the partner.
//   *
//   *         If the request is rejected due to validation errors or data issues,
//   *         the response follows a custom XML format.
//   * @throws XMLSecurityException if an unexpected exception occurs while signing
//   *                              the auth payload or encrypting the payload.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public String requestForStatement (String requestStatementPayload)
//      throws XMLSecurityException, HandlerException {
////    try {
////      KeyStore clientStore = KeyStore.getInstance("PKCS12");
////      clientStore.load(new FileInputStream(DESKERA_SSL_CERT_FILE_PATH),
////              DESKERA_SSL_CERT_PWD.toCharArray());
////      KeyManagerFactory kmf = KeyManagerFactory
////          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
////      kmf.init(clientStore, DESKERA_SSL_CERT_PWD.toCharArray());
////      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
////      sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
////      HttpsURLConnection
////          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());
//    Client client = new Client(new URLConnectionClientHandler(
//        new HttpURLConnectionFactory() {
//          Proxy proxy = null;
//
//          public HttpURLConnection getHttpURLConnection(URL url)
//              throws IOException {
//            if (proxy == null && !HandlerConstant.PROXY_URL.isEmpty()) {
//              proxy = new Proxy(Proxy.Type.HTTP,
//                  new InetSocketAddress(HandlerConstant.PROXY_URL, 8080));
//            } else {
//              proxy = Proxy.NO_PROXY;
//            }
//            return (HttpURLConnection) url.openConnection(proxy);
//          }
//        }), new DefaultClientConfig());
//    WebResource webResource = client.resource(STATEMENT_RET_URL_UAT)
//        .queryParam("client_id", getClientId());
//    Builder builder = webResource.accept(MediaType.APPLICATION_OCTET_STREAM)
//        .accept(MediaType.APPLICATION_XML);
//    builder.header(HttpHeaders.AUTHORIZATION,"Bearer " + oAuthToken);
//    String statementRetrievalPayload_SignedEncrypted = signAndEncryptXMLForCiti(
//        requestStatementPayload);
//    ClientResponse clientResponse = builder.type(MediaType.APPLICATION_XML)
//        .post(ClientResponse.class, statementRetrievalPayload_SignedEncrypted);
//    return clientResponse.getEntity(String.class);
////    } catch (IOException | CertificateException | NoSuchAlgorithmException |
////        UnrecoverableKeyException | KeyStoreException | KeyManagementException e) {
////      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
////      throw new HandlerException(e.getMessage());
////    }
//  }
//
//  /**
//   * Authentication Calling Logic: establish handshake through keys.
//   *
//   * @param oAuthPayload request body in xml.
//   * @return response received from the successful handshake with Citi API.
//   * @throws XMLSecurityException if an unexpected exception occurs while signing
//   *                              the auth payload or encrypting the payload.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  public String authenticate (String oAuthPayload) throws XMLSecurityException,
//      HandlerException {
//    try {
//      KeyStore clientStore = KeyStore.getInstance("PKCS12");
//      clientStore.load(new FileInputStream(DESKERA_SSL_CERT_FILE_PATH),
//          DESKERA_SSL_CERT_PWD.toCharArray());
//      KeyManagerFactory kmf = KeyManagerFactory
//          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
//      kmf.init(clientStore, DESKERA_SSL_CERT_PWD.toCharArray());
//
//      KeyStore trustStore = KeyStore.getInstance("JKS");
//      trustStore.load(new FileInputStream(CITI_SSL_CERT_FILE_PATH),
//          CITI_SSL_CERT_PWD.toCharArray());
//      TrustManagerFactory tmf = TrustManagerFactory
//          .getInstance(TrustManagerFactory.getDefaultAlgorithm());
//      tmf.init(trustStore);
//
//      SSLContext sslContext = SSLContext.getInstance("TLSv1.2"); // The SSL standard
//      sslContext.init(
//          kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
//      HttpsURLConnection
//          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());
//      Client client = new Client(new URLConnectionClientHandler(
//          new HttpURLConnectionFactory() {
//            Proxy proxy = Proxy.NO_PROXY;
//
//            public HttpURLConnection getHttpURLConnection(URL url)
//                throws IOException {
//              return (HttpURLConnection) url.openConnection(proxy);
//            }
//          }), new DefaultClientConfig());
//      WebResource webResource = client.resource(OAUTH_URL_UAT);
//      WebResource.Builder builder = webResource.type(MediaType.APPLICATION_XML);
//      builder.header(HttpHeaders.AUTHORIZATION, "Basic "
//          + Base64.encodeBase64String((getClientId() + ":" + getSecretKey())
//          .getBytes()).replaceAll("([\\r\\n])", ""));
//      String oAuthPayload_SignedEncrypted = signAndEncryptXMLForCiti(oAuthPayload);
//      ClientResponse clientResponse = builder.post(ClientResponse.class,
//          oAuthPayload_SignedEncrypted);
//      return clientResponse.getEntity(String.class);
//    } catch (NoSuchAlgorithmException | UnrecoverableKeyException |
//        KeyManagementException | KeyStoreException | IOException |
//        CertificateException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
}
