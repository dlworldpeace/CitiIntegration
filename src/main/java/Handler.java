package main.java;

import static main.java.BankFormatConverter.convertCamt052ToJson;
import static main.java.BankFormatConverter.convertPaIn002ToJson;
import static main.java.Constant.*;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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

  /* Class-level Constants */

  public static final Boolean isPROD = false; // is UAT otherwise

  /* Instance-level Variables */

  private String oauthToken;
  private KeyStore ks;

  /* Setters and Getters */

  private void setOAuthToken(String oauthtoken) {
    this.oauthToken = oauthtoken;
  }

  /* Keys */

  /**
   * get client id to be used in request header.
   *
   * @return client id.
   * @throws HandlerException custom exception for Handler class.
   */
  public static String getClientId() throws HandlerException {
    try {
      Path path = isPROD
          ? Paths.get(DESKERA_CLIENT_ID_FILE_PATH_PROD)
          : Paths.get(DESKERA_CLIENT_ID_FILE_PATH_UAT);
      return new String(Files.readAllBytes(path)).trim();
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
  public static String getSecretKey() throws HandlerException {
    try {
      Path path = isPROD
          ? Paths.get(DESKERA_SECRET_KEY_FILE_PATH_PROD)
          : Paths.get(DESKERA_SECRET_KEY_FILE_PATH_UAT);
      return new String(Files.readAllBytes(path)).trim();
    } catch (IOException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Load Keystore file that has all certs.
   *
   * @param ksPath String path to the .p12 keystore file in the file system
   * @param ksPswd String password to access this keystore
   * @throws HandlerException custom exception for Handler class.
   */
  public void loadKeystore(String ksPath, String ksPswd) throws HandlerException {
    try {
      ks = KeyStore.getInstance("PKCS12");
      FileInputStream fis = new FileInputStream(ksPath);
      ks.load(fis, ksPswd.toCharArray());
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
   * @param ksAlias hash key of the set of cert and key contained in the keystore
   * @return client signing cert.
   * @throws HandlerException custom exception for Handler class.
   */
  public X509Certificate getClientSigningCert(String ksAlias)
      throws HandlerException {
    try {
      X509Certificate signCert = (X509Certificate) ks.getCertificate(ksAlias);
      signCert.checkValidity();
      return signCert;
    } catch (CertificateNotYetValidException | CertificateExpiredException
        | KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Getting private client signing Key.
   *
   * @param ksAlias hash key of the set of cert and key contained in the keystore
   * @param ksPswd String password to access this keystore
   * @return PrivateKey client private key.
   * @throws HandlerException custom exception for Handler class.
   */
  public PrivateKey getClientPrivateKey(String ksAlias, String ksPswd)
      throws HandlerException {
    try {
      return (PrivateKey) ks.getKey(ksAlias, ksPswd.toCharArray());
    } catch (NoSuchAlgorithmException | UnrecoverableKeyException
        | KeyStoreException e) {
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
  private static PublicKey getCitiPublicKey() throws HandlerException {
    try {
      CertificateFactory fact = CertificateFactory.getInstance("X.509");
      FileInputStream is = isPROD
          ? new FileInputStream(CITI_PUBLIC_KEY_PATH_PROD)
          : new FileInputStream(CITI_PUBLIC_KEY_PATH_UAT);
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
  public static X509Certificate getCitiSigningCert() throws HandlerException {
    try {
      CertificateFactory fact = CertificateFactory.getInstance("X.509");
      FileInputStream is = isPROD
          ? new FileInputStream(CITI_SIGNING_CERT_PATH_PROD)
          : new FileInputStream(CITI_SIGNING_CERT_PATH_UAT);
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
  public static Document convertXmlStrToDoc(String xmlPayload)
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
  public static String convertDocToXmlStr(Document xmlDoc) throws HandlerException {
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
  public static void signXmlPayloadDoc(Document xmlDoc, X509Certificate signCert,
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
   * Encrypt the signed XML payload document.
   *
   * @param signedXmlDoc signed XML document.
   * @param publicEncryptKey public key used to encrypt the doc.
   * @throws XMLEncryptionException if an unexpected exception occurs while
   *                                encrypting the signed doc.
   * @throws HandlerException custom exception for Handler class.
   */
  public static Document encryptSignedXmlPayloadDoc(Document signedXmlDoc,
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

    String algorithmUri = XMLCipher.RSA_v1dot5;
    XMLCipher keyCipher = XMLCipher.getInstance(algorithmUri);
    keyCipher.init(XMLCipher.WRAP_MODE, publicEncryptKey);
    EncryptedKey encryptedKey = keyCipher
        .encryptKey(signedXmlDoc, symmetricKey);
    Element rootElement = signedXmlDoc.getDocumentElement();
    algorithmUri = XMLCipher.TRIPLEDES;
    XMLCipher xmlCipher = XMLCipher.getInstance(algorithmUri);
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
   * @param payloadXml payload string in xml.
   * @return encrypted signed payload string.
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload.
   * @throws HandlerException custom exception for Handler class.
   */
  public String signAndEncryptXmlForCiti(String payloadXml)
      throws XMLSecurityException, HandlerException {
    Document payloadDoc = convertXmlStrToDoc(payloadXml);
    PrivateKey clientPrivateKey = isPROD
        ? getClientPrivateKey(KEYSTORE_ALIAS_PROD, KEYSTORE_PASSWORD_PROD)
        : getClientPrivateKey(KEYSTORE_ALIAS_UAT, KEYSTORE_PASSWORD_UAT);
    X509Certificate clientSigningCert = isPROD
        ? getClientSigningCert(KEYSTORE_ALIAS_PROD)
        : getClientSigningCert(KEYSTORE_ALIAS_UAT);
    signXmlPayloadDoc(payloadDoc, clientSigningCert, clientPrivateKey);
    String signed = convertDocToXmlStr(payloadDoc);
    PublicKey citiPublicKey = getCitiPublicKey();
    Document encryptedSignedXmlPayloadDoc = encryptSignedXmlPayloadDoc(
        payloadDoc, citiPublicKey);
    return convertDocToXmlStr(encryptedSignedXmlPayloadDoc);
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
  public static Document decryptEncryptedAndSignedXml(Document encryptedSignedDoc,
      PrivateKey privateDecryptKey) throws XMLEncryptionException, HandlerException {

    org.apache.xml.security.Init.init();
    Element docRoot = encryptedSignedDoc.getDocumentElement();
    Node dataEl;
    if ("http://www.w3.org/2001/04/xmlenc#".equals(docRoot.getNamespaceURI())
        && "EncryptedData".equals(docRoot.getLocalName())) {
      dataEl = docRoot;
    } else {
      NodeList childs = docRoot
          .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#",
              "EncryptedData");
      if (childs == null || childs.getLength() == 0) {
        throw new HandlerException(
            "Encrypted Data not found on XML Document while parsing to decrypt");
      }
      dataEl = childs.item(0);
    }
    if (dataEl == null) {
      throw new HandlerException(
          "Encrypted Data not found on XML Document while parsing to decrypt");
    }
    NodeList keyList = ((Element) dataEl)
        .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#",
            "EncryptedKey");
    if (keyList == null || keyList.getLength() == 0) {
      throw new HandlerException(
          "Encrypted Key not found on XML Document while parsing to decrypt");
    }
    Node keyEl = keyList.item(0);
    XMLCipher cipher = XMLCipher.getInstance();
    cipher.init(XMLCipher.DECRYPT_MODE, null);
    EncryptedData encryptedData = cipher
        .loadEncryptedData(encryptedSignedDoc, (Element) dataEl);
    EncryptedKey encryptedKey = cipher
        .loadEncryptedKey(encryptedSignedDoc, (Element) keyEl);
    if (encryptedData != null && encryptedKey != null) {
      String encAlgoUrl = encryptedData.getEncryptionMethod().getAlgorithm();
      XMLCipher keyCipher = XMLCipher.getInstance();
      keyCipher.init(XMLCipher.UNWRAP_MODE, privateDecryptKey);
      Key encryptionKey = keyCipher.decryptKey(encryptedKey, encAlgoUrl);
      cipher = XMLCipher.getInstance();
      cipher.init(XMLCipher.DECRYPT_MODE, encryptionKey);
      try {
        Document decryptedDoc = cipher
            .doFinal(encryptedSignedDoc, (Element) dataEl);
        decryptedDoc.normalize();
        return decryptedDoc;
      } catch (Exception e) {
        Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
        throw new HandlerException(e.getMessage());
      }
    } else {
      throw new HandlerException(
          "No encrypted data or encrypted key to proceed "
              + "with decrypting the response XML");
    }
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
  public static void verifyDecryptedXml(Document decryptedDoc,
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
      String baseUri = "file:";
      XMLSignature signature = new XMLSignature((Element) sigElement.item(0),
          baseUri);
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
   * @param encryptedSignedXmlResponse xml response to be decrypted followed by
   *                                   verified.
   * @return verified and decrypted xml response string.
   * @throws CertificateEncodingException if an unexpected exception occurs while
   *                                      extracting cert info.
   * @throws XMLSecurityException if an unexpected exception occurs while
   *                              verifying the signature.
   * @throws HandlerException custom exception for Handler class.
   */
  public String decryptAndVerifyXmlFromCiti(String encryptedSignedXmlResponse)
      throws HandlerException, XMLSecurityException, CertificateEncodingException {
    PrivateKey clientPrivateDecryptionKey = isPROD
        ? getClientPrivateKey(KEYSTORE_ALIAS_PROD, KEYSTORE_PASSWORD_PROD)
        : getClientPrivateKey(KEYSTORE_ALIAS_UAT, KEYSTORE_PASSWORD_UAT);
    Document encryptedSignedXmlResponseDoc =
        convertXmlStrToDoc(encryptedSignedXmlResponse);
    Document signedXmlResponseDoc = decryptEncryptedAndSignedXml(
        encryptedSignedXmlResponseDoc, clientPrivateDecryptionKey);
    X509Certificate citiVerificationKey = getCitiSigningCert();
    verifyDecryptedXml(signedXmlResponseDoc, citiVerificationKey);
    return convertDocToXmlStr(signedXmlResponseDoc);
  }

  /* API Calling Logics */

  /**
   * parsing logic to extract only necessary info from the error response in xml.
   *
   * @param errorResponse the decrypted and verified error response
   * @return the condensed error message in one line
   * @throws HandlerException if an unexpected event occurs when condensing the
   *                          message
   */
  public static String condenseErrorResponse(String errorResponse)
      throws HandlerException {
    try {
      String errorMsg = "";
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document document = builder.parse(
          new InputSource(new StringReader(errorResponse)));
      Element rootElement = document.getDocumentElement();
      rootElement.normalize();
      NodeList httpCode = rootElement.getElementsByTagName("httpCode");
      if (httpCode != null && httpCode.getLength() > 0) {
        NodeList subList = httpCode.item(0).getChildNodes();

        if (subList != null && subList.getLength() > 0) {
          errorMsg +=  subList.item(0).getNodeValue() + ". ";
        }
      }
      NodeList httpMessage = rootElement.getElementsByTagName("httpMessage");
      if (httpMessage != null && httpMessage.getLength() > 0) {
        NodeList subList = httpMessage.item(0).getChildNodes();

        if (subList != null && subList.getLength() > 0) {
          errorMsg +=  subList.item(0).getNodeValue() + ". ";
        }
      }
      NodeList moreInfo = rootElement.getElementsByTagName("moreInformation");
      if (moreInfo != null && moreInfo.getLength() > 0) {
        NodeList subList = moreInfo.item(0).getChildNodes();

        if (subList != null && subList.getLength() > 0) {
          errorMsg +=  subList.item(0).getNodeValue() + ". ";
        }
      }

      if (!errorMsg.isEmpty()) {
        return errorMsg;
      }
      throw new HandlerException("Fail to extract error info from XML");
    } catch (ParserConfigurationException | IOException | SAXException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Abstraction of HTTP client webservice logic.
   *
   * @param url URL of the server for sending the http request to
   * @param payload not yet signed nor encrypted XML payload
   * @return the http response body
   * @throws HandlerException if an unexpected exception occurs when signing and
   *                          encrypting the request payload or,
   *                          when sending the http request in exchange for http
   *                          response or,
   *                          when verifying and decrypting the error response
   */
  private byte[] handleHttp(Map<String, String> headerList, String payload,
      String url) throws HandlerException {

    try {
      RestTemplate restTemplate = new RestTemplate();
      org.springframework.http.HttpHeaders headers =
          new org.springframework.http.HttpHeaders();
      headers.setAccept(Arrays.asList(APPLICATION_XML, APPLICATION_OCTET_STREAM));
      for (Map.Entry<String, String> entry : headerList.entrySet()) {
        headers.set(entry.getKey(), entry.getValue());
      }
      String signedEncryptedXmlPayload = signAndEncryptXmlForCiti(payload);
      HttpEntity<String> entity =
          new HttpEntity<>(signedEncryptedXmlPayload, headers);
      ResponseEntity<?> responseEntity = restTemplate
          .exchange(url, HttpMethod.POST, entity, byte[].class);
      return (byte[]) responseEntity.getBody();
    } catch (HttpStatusCodeException e) {
      String errorResponse = e.getResponseBodyAsString();
      String errorResponseDecrypted;
      try {
        errorResponseDecrypted = decryptAndVerifyXmlFromCiti(errorResponse);
      } catch (CertificateEncodingException | XMLSecurityException ex) {
        Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, ex);
        throw new HandlerException(
            "Decrypting and verifying error response body: " + ex.getMessage());
      }
      String errorMsg = condenseErrorResponse(errorResponseDecrypted);
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, errorMsg);
      throw new HandlerException(errorMsg);
    } catch (XMLSecurityException | RestClientException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Authentication Calling Logic: establish handshake through keys.
   *
   * @param clientId account-specific identifier
   * @param secretKey account-specific secret key
   * @param oauthpayload request body in xml.
   * @return response received from the successful handshake with Citi API.
   * @throws HandlerException custom exception for Handler class.
   */
  public void requestOAuth(String clientId, String secretKey,
      String oauthpayload) throws HandlerException {

    try {
      KeyStore clientStore = KeyStore.getInstance("PKCS12");
      FileInputStream deskeraIs = isPROD
          ? new FileInputStream(DESKERA_SSL_CERT_FILE_PATH_PROD)
          : new FileInputStream(DESKERA_SSL_CERT_FILE_PATH_UAT);
      char[] deskeraPswd = isPROD
          ? DESKERA_SSL_CERT_PWD_PROD.toCharArray()
          : DESKERA_SSL_CERT_PWD_UAT.toCharArray();
      clientStore.load(deskeraIs, deskeraPswd);
      KeyManagerFactory kmf = KeyManagerFactory
          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(clientStore, deskeraPswd);

      KeyStore trustStore = KeyStore.getInstance("JKS");
      FileInputStream citiIs = isPROD
          ? new FileInputStream(CITI_SSL_CERT_FILE_PATH_PROD)
          : new FileInputStream(CITI_SSL_CERT_FILE_PATH_UAT);
      char[] citiPswd = isPROD
          ? CITI_SSL_CERT_PWD_PROD.toCharArray()
          : CITI_SSL_CERT_PWD_UAT.toCharArray();
      trustStore.load(citiIs, citiPswd);
      TrustManagerFactory tmf = TrustManagerFactory
          .getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);

      SSLContext sslContext = SSLContext
          .getInstance("TLSv1.2"); // The SSL standard
      sslContext.init(
          kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
      HttpsURLConnection
          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());

      Map<String, String> headerList = new HashMap<>();
      headerList.put("Content-Type", "application/xml");
      headerList.put(HttpHeaders.AUTHORIZATION, "Basic "
          + Base64.encodeBase64String((clientId + ":" + secretKey)
          .getBytes()).replaceAll("([\\r\\n])", ""));

      String url = isPROD ? OAUTH_URL_PROD : OAUTH_URL_UAT;
      String response = new String(handleHttp(headerList, oauthpayload, url));
      String decryptedVerifiedResponse = decryptAndVerifyXmlFromCiti(response);
      String oauthToken = parseAuthOrPayInitResponse(
          convertXmlStrToDoc(decryptedVerifiedResponse), TYPE_AUTH, TAG_NAME_AUTH);
      this.setOAuthToken(oauthToken);

    } catch (IOException | CertificateException | UnrecoverableKeyException
        | NoSuchAlgorithmException | KeyStoreException | KeyManagementException
        | XMLSecurityException | XPathExpressionException e) {
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
  public static String parseAuthOrPayInitResponse(Document responseDoc, String type,
      String tagName) throws HandlerException, XPathExpressionException {

    XPath xpath = XPathFactory.newInstance().newXPath();

    String errorInResponse = "";
    Element docRoot = responseDoc.getDocumentElement();
    if (docRoot == null || docRoot.getNodeName() == null) {
      errorInResponse = "Response Message Doesn't have expected Information";
    } else {
      if (docRoot.getNodeName().equalsIgnoreCase("errormessage")) {
        StringBuilder errorReponseSb = new StringBuilder();

        String httpCodeTag = null;
        String httpMessage = null;
        String moreInformation = null;

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

        errorReponseSb.append(httpCodeTag).append(": ")
            .append(httpMessage)
            .append(": ").append(moreInformation);
        errorInResponse = errorReponseSb.toString();
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
   * Payment Initiation API: Generate Base64 request payload from ISO XML Payload.
   *
   * @param isoPayInXml input xml string.
   * @return base64 string generated from {@code isoPayInXML} placed in
   *         {@code <Request><paymentBase64>} tag.
   * @throws HandlerException a custom exception for Handler class is triggered
   *                          when the input is not of the correct ISO XML form
   *                          or unexpected event occurred during XML parsing.
   */
  public static String generateBase64PayloadFromIsoXml(String isoPayInXml)
      throws HandlerException {

    if (isoPayInXml.trim().equals("")) {
      String message = "Fatal: Non-ISO format string received";
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, message);
      throw new HandlerException(message);
    }

    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      factory.setNamespaceAware(true);
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document doc = builder.parse(
          new ByteArrayInputStream(isoPayInXml.getBytes(StandardCharsets.UTF_8)));
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

    StringBuilder xmlStrSb = new StringBuilder();
    final char[] pem_array = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
        'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
        'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
        'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
        'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', '+', '/'
    };
    byte[] inBuff = isoPayInXml.getBytes();
    int numBytes = inBuff.length;
    if (numBytes == 0) {
      return "";
    }
    byte[] outBuff = new byte[(numBytes - 1) / 3 + 1 << 2];
    int pos = 0;
    int len = 3;
    for (int j = 0; j < numBytes; j += 3) {
      if (j + 3 > numBytes) {
        len = numBytes - j;
      }
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
   * necessary data required in ISOXML V3 (pain.001.001.03).
   *
   * @param clientId account-specific identifier
   * @param payload data in ISOXML V3 format.
   * @return a json response that denotes whether the payment has passed the basic
   *         validations. The Partner has the ability to view transaction or
   *         payment status at any later point using the Payment Status Inquiry
   *         API. The response also contains an APITrackingID (Message ID) as
   *         its URI.
   * @throws HandlerException custom exception for Handler class.
   */
  public String initiatePayment(String clientId, String payload) throws HandlerException {
    if (oauthToken == null) {
      HandlerException e =
          new HandlerException("Other api is called before authentication");
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw e;
    }
    try {
      Map<String, String> headerList = new HashMap<>();
      headerList.put("Content-Type", "application/xml");
      headerList.put(PAYMENT_TYPE_HEADER, OUTGOING_PAYMENT_TYPE);
      headerList.put(HttpHeaders.AUTHORIZATION, "Bearer " + oauthToken);
      String base64Payload = generateBase64PayloadFromIsoXml(payload);
      String url = isPROD
          ? PAY_INIT_URL_PROD + clientId
          : PAY_INIT_URL_UAT + clientId;
      String resEncrypted = new String(handleHttp(headerList, base64Payload, url));
      final String resPlain = decryptAndVerifyXmlFromCiti(resEncrypted);
      return parseAuthOrPayInitResponse(
          convertXmlStrToDoc(resPlain), TYPE_PAY_INIT, TAG_NAME_PAY_INIT);
    } catch (XMLSecurityException | CertificateEncodingException
        | XPathExpressionException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Payment status inquiry logic using the unique EndToEndId specified in the
   * payment initiation payload. This is done via the Enhanced Payment
   * Status Inquiry API.
   *
   * @param clientId account-specific identifier
   * @param endToEndId payment transaction URI
   * @return a json response that follows the ISOXML (pain.002.001.03) standards.
   * @throws HandlerException custom exception for Handler class.
   */
  public String checkPaymentStatus(String clientId, String endToEndId)
      throws HandlerException {
    if (oauthToken == null) {
      HandlerException e =
          new HandlerException("Other api is called before authentication");
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw e;
    }
    try {
      String payload = new String(Files.readAllBytes(Paths.get(
          "src/test/resources/sample/EnhancedPaymentStatusInquiry/"
              + "XML Request/paymentInq_Request_EndToEndId_Format.txt")))
          .replace("placeholder", endToEndId);
      Map<String, String> headerList = new HashMap<>();
      headerList.put("Content-Type", "application/xml");
      headerList.put(HttpHeaders.AUTHORIZATION, "Bearer " + oauthToken);
      String url = isPROD
          ? PAY_ENHANCED_STATUS_URL_PROD + clientId
          : PAY_ENHANCED_STATUS_URL_UAT + clientId;
      String resEncrypted = new String(handleHttp(headerList, payload, url));
      String resPlain = decryptAndVerifyXmlFromCiti(resEncrypted);
      return convertPaIn002ToJson(resPlain);
    } catch (XMLSecurityException | CertificateEncodingException | IOException
        | BankFormatConverterException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Balance inquiry logic.
   *
   * @param clientId account-specific identifier
   * @param payload Payload that contains account number or branch number
   * @return a json response in the format of camt.052.001.02
   * @throws HandlerException custom exception for Handler class
   */
  public String checkBalance(String clientId, String payload) throws HandlerException {
    if (oauthToken == null) {
      HandlerException e =
          new HandlerException("Other api is called before authentication");
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw e;
    }
    try {
      Map<String, String> headerList = new HashMap<>();
      headerList.put("Content-Type", "application/xml");
      headerList.put(HttpHeaders.AUTHORIZATION, "Bearer " + oauthToken);
      String url = isPROD
          ? BALANCE_INQUIRY_URL_PROD + clientId
          : BALANCE_INQUIRY_URL_UAT + clientId;
      String resEncrypted = new String(handleHttp(headerList, payload, url));
      final String resPlain = decryptAndVerifyXmlFromCiti(resEncrypted);
      return convertCamt052ToJson(resPlain);
    } catch (XMLSecurityException | CertificateEncodingException
        | BankFormatConverterException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Statement initiation logic.
   *
   * @param clientId account-specific identifier
   * @param payLoad data in XML format.
   * @return a response that contains the statement ID which can be used to call
   *         statement retrieval API to obtain the specific statement file.
   * @throws HandlerException custom exception for Handler class.
   */
  public String initiateStatement(String clientId, String payLoad) throws HandlerException {
    if (oauthToken == null) {
      HandlerException e =
          new HandlerException("Other api is called before authentication");
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw e;
    }
    try {
      Map<String, String> headerList = new HashMap<>();
      headerList.put("Content-Type", "application/xml");
      headerList.put(HttpHeaders.AUTHORIZATION, "Bearer " + oauthToken);
      String url = isPROD
          ? STATEMENT_INIT_URL_PROD + clientId
          : STATEMENT_INIT_URL_UAT + clientId;
      String resEncrypted = new String(handleHttp(headerList, payLoad, url));
      String resInitStat = decryptAndVerifyXmlFromCiti(resEncrypted);
      return extractStatementId(resInitStat);
    } catch (XMLSecurityException | CertificateEncodingException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * parsing logic to extract only the statement id from the statement initiation
   * response after the latter is decrypted and verified by the client.
   *
   * @param xml the decrypted and verified statement initiation response.
   * @return the attached decryption key used to decrypt the statement file.
   * @throws HandlerException if an unexpected event occurs when taking out the
   *                          statement id from the {@code XML}.
   */
  public static String extractStatementId(String xml)
      throws HandlerException {
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document document = builder.parse(new InputSource(new StringReader(xml)));
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
   * @param xmlResponse a MIME response which has 2 parts. First part is of XML
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
  public static HashMap<String, Object> parseMimeResponse(byte[] xmlResponse)
      throws HandlerException {
    try {
      String responseStatRetXmlStr = "";
      byte[] encryptedStatByteArray = null;
      /* need to import javax.activation.DataSource for this below */
      MimeMultipart mp = new MimeMultipart(
          new ByteArrayDataSource(xmlResponse, TEXT_XML_VALUE));
      for (int i = 0; i < mp.getCount(); i++) {
        BodyPart bodyPart = mp.getBodyPart(i);

        if (bodyPart.isMimeType("text/xml")
            || bodyPart.isMimeType("application/xml")) {
          if (SharedByteArrayInputStream.class
              .equals(bodyPart.getContent().getClass())) {
            responseStatRetXmlStr = IOUtils.toString((SharedByteArrayInputStream)
                    bodyPart.getContent(), StandardCharsets.UTF_8);
          } else {
            responseStatRetXmlStr = (String) bodyPart.getContent();
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

      if (responseStatRetXmlStr.isEmpty() || encryptedStatByteArray == null) {
        throw new HandlerException(
            "Fail to parse the MIME response into 2 parts");
      }
      HashMap<String, Object> result = new HashMap<>();
      result.put("ENCRYPTED_KEY", responseStatRetXmlStr);
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
  public static byte[] des3DecodeCbc(String decryptionKey, byte[] input)
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
    } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException
        | InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException
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
   * @param xml the decrypted first section of statement retrieval response.
   * @return the attached decryption key used to decrypt the statement file.
   * @throws HandlerException if an unexpected event occurs when taking out the
   *                          attachmentDecryptionKey value from the {@code XML}
   *                          string.
   */
  public static String extractAttachmentDecryptionKey(String xml)
      throws HandlerException {
    try {
      DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
      DocumentBuilder builder = factory.newDocumentBuilder();
      Document document = builder.parse(new InputSource(new StringReader(xml)));
      Element rootElement = document.getDocumentElement();
      NodeList decryptionKeyElement =
          rootElement.getElementsByTagName("ns2:attachmentDecryptionKey");
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
   * @param clientId account-specific identifier
   * @param statementId unique statement identifier
   * @param url the address that we are sending the statement retrieval request
   *            to.
   * @return the expected statement file decrypted
   * @throws HandlerException if an unexpected exception occurs while requesting
   *                          for the specific statement file from the server
   */
  public String retrieveStatement(String clientId, String statementId, String url)
      throws HandlerException {
    try {
      final String payload = new String(Files.readAllBytes(Paths.get(
          "src/test/resources/sample/StatementRetrieval/"
              + "XML Request/StatementRetrievalRequest_Plain_Format.txt")))
          .replace("placeholder", statementId);
      Map<String, String> headerList = new HashMap<>();
      headerList.put("Content-Type", "application/xml");
      headerList.put(HttpHeaders.AUTHORIZATION, "Bearer " + oauthToken);
      HashMap<String, Object> body = parseMimeResponse(
          handleHttp(headerList, payload, url + clientId));
      String firstHalf =
          decryptAndVerifyXmlFromCiti((String) body.get("ENCRYPTED_KEY"));
      String decryptionKey = extractAttachmentDecryptionKey(firstHalf);
      return new String(
          des3DecodeCbc(decryptionKey, (byte[]) body.get("ENCRYPTED_FILE")));
    } catch (XMLSecurityException | CertificateEncodingException | IOException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Method overloader to get the intended statement file using its statement ID.
   *
   * @param clientId account-specific identifier
   * @param statementId unique statement identifier
   * @return the expected statement file decrypted
   * @throws HandlerException if an unexpected exception occurs while requesting
   *                          for the specific statement file from the server
   */
  public String retrieveStatement(String clientId, String statementId)
      throws HandlerException {
    if (oauthToken == null) {
      HandlerException e =
          new HandlerException("Other api is called before authentication");
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw e;
    }
    String url = isPROD
        ? STATEMENT_RET_URL_PROD + clientId
        : STATEMENT_RET_URL_UAT + clientId;
    return retrieveStatement(clientId, statementId, url);
  }

}
