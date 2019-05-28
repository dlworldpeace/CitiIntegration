import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.WebResource.Builder;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import com.sun.jersey.client.urlconnection.HttpURLConnectionFactory;
import com.sun.jersey.client.urlconnection.URLConnectionClientHandler;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
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
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
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
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpStatusCodeException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * The API that supports all connection features to CitiSecurity
 *
 * @author Sagar Mahamuni and Xiao Delong
 * @version 1.0
 * @since 2019-05-22
 */

public class Handler {

  /* Encryption Logic */

  /**
   * Load Keystore file that has all certs
   *
   * @throws HandlerException custom exception for Handler class
   */
  public static void loadKeystore () throws HandlerException {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      FileInputStream fis = new FileInputStream(HandlerConstant.keyStoreFilePath);
      ks.load(fis, HandlerConstant.keyStorePwd.toCharArray());
      fis.close();
    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException |
        IOException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Getting the XML payload as Document object
   *
   * @param xmlPayload original payload in xml format
   * @return converted document object
   * @throws HandlerException custom exception for Handler class
   */
  public static Document convertXMLPayloadToDoc (String xmlPayload)
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
   * Getting public client signing key
   *
   * @return client public key
   * @throws HandlerException custom exception for Handler class
   */
  public static X509Certificate getClientPublicKey () throws HandlerException {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      X509Certificate signCert = (X509Certificate) ks
          .getCertificate(HandlerConstant.clientSignKeyAlias);
      signCert.checkValidity();
      return signCert;
    } catch (CertificateNotYetValidException | CertificateExpiredException |
        KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Getting private client signing Key
   *
   * @return PrivateKey client private key
   * @throws HandlerException custom exception for Handler class
   */
  public static PrivateKey getClientPrivateKey () throws HandlerException {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      return (PrivateKey) ks.getKey(
          HandlerConstant.clientSignKeyAlias, HandlerConstant.keyStorePwd.toCharArray());
    } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Signing the XML payload document
   *
   * @param xmlDoc xml document to be signed
   * @param signCert certificate to be added in
   * @param privateSignKey private key used to sign the document
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the {@code xmlDoc}
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
   * Getting public citi encryption key
   *
   * @return citi public key
   * @throws HandlerException custom exception for Handler class
   */
  public static PublicKey getCitiPublicKey () throws HandlerException {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      X509Certificate encryptCert = (X509Certificate) ks
          .getCertificate(HandlerConstant.citiEncryptKeyAlias);
      encryptCert.checkValidity();
      return encryptCert.getPublicKey();
    } catch (CertificateNotYetValidException | CertificateExpiredException |
        KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Encrypt the signed XML payload document
   *
   * @param signedXmlDoc signed XML document
   * @param publicEncryptKey public key used to encrypt the doc
   * @throws XMLEncryptionException if an unexpected exception occurs while
   *                                encrypting the signed doc
   * @throws HandlerException custom exception for Handler class
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
   * Convert the Document object to String value
   *
   * @return string value of the document
   * @throws HandlerException custom exception for Handler class
   */
  public static String convertDocToString (Document xmlDoc) throws HandlerException {
    try {
      TransformerFactory tf = TransformerFactory.newInstance();
      Transformer transformer = tf.newTransformer();
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
      StringWriter writer = new StringWriter();
      transformer.transform(new DOMSource(xmlDoc), new StreamResult(writer));

      // TODO check what kind of string value is returned: XML?

      return writer.getBuffer().toString();
    } catch (TransformerException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Sign xml payload using our private key and citi cert, followed by encrypting
   * it using citi public key
   *
   * @param payloadXML payload string in xml
   * @return encrypted signed payload string
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload
   * @throws HandlerException custom exception for Handler class
   */
  public static String signAndEncryptXML (String payloadXML)
      throws XMLSecurityException, HandlerException {
    Document payloadDoc = convertXMLPayloadToDoc(payloadXML);
    PrivateKey clientPrivateKey = getClientPrivateKey();
    X509Certificate clientSigningCert = getClientPublicKey();
    signXMLPayloadDoc(payloadDoc, clientSigningCert, clientPrivateKey);
    PublicKey citiPublicKey = getCitiPublicKey();
    Document encryptedSignedXMLPayloadDoc = encryptSignedXMLPayloadDoc(
        payloadDoc, citiPublicKey);
    return convertDocToString(encryptedSignedXMLPayloadDoc);
  }

  /* Decryption Logic */

  /**
   * Load Keystore file that has all certs
   *
   * @throws HandlerException custom exception for Handler class
   */
  public static void loadKeystoreWithAllCerts () throws HandlerException {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      FileInputStream fis = new FileInputStream(HandlerConstant.keyStoreFilePath);
      ks.load(fis, HandlerConstant.keyStorePwd.toCharArray());
      fis.close();
    } catch (IOException | CertificateException | NoSuchAlgorithmException |
        KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  // TODO remove this function since we have 2 methods that do the same job by taking diff arguments?
  /**
   * Getting the XML Payload as Document object
   *
   * @return converted document
   * @throws HandlerException custom exception for Handler class
   */
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

  /**
   * Getting public client decryption key
   *
   * @return public client decryption key
   * @throws HandlerException custom exception for Handler class
   */
  public static X509Certificate getClientPublicDecrytionKey () throws HandlerException {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      X509Certificate decryptCert = (X509Certificate) ks
          .getCertificate(HandlerConstant.clientDecryptKeyAlias);
      decryptCert.checkValidity();
      return decryptCert;
    } catch (CertificateExpiredException | CertificateNotYetValidException |
        KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Getting private client decryption key
   *
   * @return private client decryption key
   * @throws HandlerException custom exception for Handler class
   */
  public static PrivateKey getClientPrivateDecryotKey () throws HandlerException {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      return (PrivateKey) ks.getKey(HandlerConstant.clientDecryptKeyAlias,
              HandlerConstant.keyStorePwd.toCharArray());
    } catch (UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Decrypt the encrypted & signed XML Response Payload Document
   *
   * @param encryptedSignedDoc encrypted & signed XML doc
   * @param privateDecryptKey private key used to decrypt
   * @throws XMLEncryptionException if an unexpected exception occurs while
   *                                decrypting the encrypted & signed doc
   * @throws HandlerException custom exception for Handler class
   */
  public static void decryptEncryptedAndSignedXML (Document encryptedSignedDoc,
      PrivateKey privateDecryptKey) throws XMLEncryptionException, HandlerException {

    org.apache.xml.security.Init.init();
    Element docRoot = encryptedSignedDoc.getDocumentElement();
    Node dataEL = null;
    Node keyEL = null;
    if ("http://www.w3.org/2001/04/xmlenc#".equals(docRoot.getNamespaceURI())
        && "EncryptedData".equals(docRoot.getLocalName())) {
      dataEL = docRoot;
    } else {
      NodeList childs = docRoot
          .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#",
              "EncryptedData");
      if (childs == null || childs.getLength() == 0) {
        throw new HandlerException(
            "Encrypted Data not found on XML Document while parsing  to decrypt");
      }
      dataEL = childs.item(0);
    }
    if (dataEL == null) {
      throw new HandlerException(
          "Encrypted Data not found on XML Document while parsing  to decrypt");
    }
    NodeList keyList = ((Element) dataEL)
        .getElementsByTagNameNS("http://www.w3.org/2001/04/xmlenc#",
            "EncryptedKey");
    if (keyList == null || keyList.getLength() == 0) {
      throw new HandlerException(
          "Encrypted Key not found on XML Document while parsing  to decrypt");
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
      } catch (Exception e) {
        Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
        throw new HandlerException(e.getMessage());
      }
    }
    decryptedDoc.normalize(); // TODO: add inside if loop?
  }

  /**
   * Getting public citi verification key
   *
   * @return public citi verification key
   * @throws HandlerException custom exception for Handler class
   */
  public static X509Certificate getCitiVerficationKey () throws HandlerException {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      X509Certificate signVerifyCert = (X509Certificate) ks
          .getCertificate(HandlerConstant.citiVerifyKeyAlias);
      signVerifyCert.checkValidity();
      return signVerifyCert;
    } catch (CertificateNotYetValidException | CertificateExpiredException |
        KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Verifying the Signature of decrypted XML response Payload Document
   *
   * @param decryptedDoc decrypted XML doc to be verified
   * @param signVerifyCert certificate used to verify the signature of the doc
   * @throws CertificateEncodingException if an unexpected exception occurs while extracting cert info
   * @throws XMLSecurityException if an unexpected exception occurs while verifying the signature
   * @throws HandlerException custom exception for Handler class
   */
  // TODO: Check for the exception throwing
  public static void verifySignatureofDecryptedXML (Document decryptedDoc,
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
   * Decrypt Statement File
   *
   * @param encryptedStatementFile byteArray of encrypted statement file
   * @return decrypted statement file as byteArray
   * @throws HandlerException custom exception for Handler class
   */
  public static byte[] decryptStatementFile (byte[] encryptedStatementFile)
      throws HandlerException {

    String decryptionKey = "";
    NodeList nodes = evalFromString(
        "//statementRetrievalResponse//attachmentDecryptionKey",
        decryptedStatementRetrievalResponse);
    int len = (nodes != null) ? nodes.getLength() : 0;
    if (len == 1) {
      decryptionKey = nodes.item(0).getTextContent();
    }
    int ivLen = 8;
    byte[] keyiv = new byte[ivLen];
    System.arraycopy(encryptedStatementFile, 0, keyiv, 0, ivLen);
    int dataLen = encryptedStatementFile.length - ivLen;
    byte[] data = new byte[dataLen];
    System.arraycopy(encryptedStatementFile, ivLen, data, 0, dataLen);

    try {
      DESedeKeySpec spec = new DESedeKeySpec(
          Base64.decodeBase64(decryptionKey));
      SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
      Key deskey = keyfactory.generateSecret(spec);
      Cipher cipher = Cipher
          .getInstance("TripleDES/CBC/NoPadding");//PKCS5Padding NoPadding
      IvParameterSpec ips = new IvParameterSpec(keyiv);
      cipher.init(Cipher.DECRYPT_MODE, deskey, ips);
      byte[] bout = cipher.doFinal(data);
      return Base64.decodeBase64(bout);
    } catch (NoSuchAlgorithmException | InvalidKeyException |
        NoSuchPaddingException | InvalidAlgorithmParameterException |
        InvalidKeySpecException | BadPaddingException | IllegalBlockSizeException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /* Parsing Response Logic */

  /**
   * Parsing response to show error or valid message logic
   *
   * @param responseDoc document to be parsed
   * @param type "" for authType or "BASE64" for paymentType
   * @return response message
   * @throws HandlerException custom exception for Handler class
   */
  public static String handleResponse (Document responseDoc, String type)
      throws HandlerException {

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
      NodeList nodes = (NodeList) xpath.compile(xpath.compile(tagName)) // TODO: Find out what tagName is
          .evaluate(responseDoc, XPathConstants.NODESET);
      if (nodes != null && nodes.getLength() == 1) {
        String response = nodes.item(0).getNodeValue();

        if ("BASE64".equals(type)) {
          return new String(Base64.decodeBase64(response));
        } else {
          return response;
        }
      } else {
        throw new HandlerException("Empty content of responseDoc");  // TODO: Check if this logic is correct
      }
    }
  }

  /**
   * Parsing MTOM Response (Parser for Statement Retrieval Response)
   *
   * @param response MTOM response
   * @return response in byteArray
   * @throws HandlerException custom exception for Handler class
   */
  public static byte[] parseMTOPResponse (String response) throws HandlerException {
    try {
      MimeMultipart mp = new MimeMultipart(
          new ByteArrayDataSource(response, MediaType.TEXT_XML));
      for (int i = 0; i < mp.getCount(); i++) {
        BodyPart bodyPart = mp.getBodyPart(i);
        String contentType = bodyPart.getContentType();
        Logger.getLogger(Handler.class.getName()).info("ContentType==>" + contentType);
        if (bodyPart.isMimeType("text/xml")) {// if text/xml
          responseStatRetXMLStr = (String) bodyPart
              .getContent(); // TODO: Find out why is this never used
        } else {
          ByteArrayInputStream bais = (ByteArrayInputStream) bodyPart
              .getContent();
          ByteArrayOutputStream buffer = new ByteArrayOutputStream();
          int nRead;
          byte[] data = new byte[1024];
          while ((nRead = bais.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
          }
          buffer.flush();
          return buffer.toByteArray();
        }
      }
    } catch (MessagingException | IOException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /* API Calling Logics */

  /**
   * Authentication Calling Logic: establish handshake through keys
   *
   * @param oAuthPayload request body in xml
   * @return response received from the successful handshake with Citi API
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload
   * @throws HandlerException custom exception for Handler class
   */
  public static String authenticate (String oAuthPayload)
      throws XMLSecurityException, HandlerException {
    try {
      KeyStore clientStore = KeyStore.getInstance("PKCS12");
      clientStore
          .load(new FileInputStream(HandlerConstant.sslCertFilePath),
              HandlerConstant.certPwd.toCharArray());

      KeyManagerFactory kmf = KeyManagerFactory
          .getInstance(KeyManagerFactory.getDefaultAlgorithm());

      kmf.init(clientStore, HandlerConstant.certPwd.toCharArray());

      SSLContext sslContext = SSLContext
          .getInstance("TLSv1.2"); // SSL standard
      sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
      HttpsURLConnection
          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());

      Client client = new Client(new URLConnectionClientHandler(
          new HttpURLConnectionFactory() {
            Proxy proxy = null;

            public HttpURLConnection getHttpURLConnection(URL url)
                throws IOException {
              if (proxy == null && !HandlerConstant.proxyURL.isEmpty()) {
                proxy = new Proxy(Proxy.Type.HTTP,
                    new InetSocketAddress(HandlerConstant.proxyURL, 8080));
              } else {
                proxy = Proxy.NO_PROXY;
              }
              return (HttpURLConnection) url.openConnection(proxy);
            }
          }), new DefaultClientConfig());
      WebResource webResource = client.resource(HandlerConstant.oAuthURL_UAT);
      WebResource.Builder builder = webResource.type(MediaType.APPLICATION_XML);
      builder.header(HttpHeaders.AUTHORIZATION, "Basic " + Base64.encodeBase64String(
              (HandlerConstant.clientID + ":" + HandlerConstant.clientSecretKey)
                  .getBytes()).replaceAll("([\\r\\n])", ""));
      String oAuthPayload_SignedEncrypted = signAndEncryptXML(oAuthPayload);
      ClientResponse clientResponse = builder.post(ClientResponse.class,
              oAuthPayload_SignedEncrypted);
      return clientResponse.getEntity(String.class);
    } catch (IOException | CertificateException | NoSuchAlgorithmException |
        UnrecoverableKeyException | KeyManagementException | KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Payment Initiation API: Generate Base64 Input Request from ISO XML Payload
   *
   * @param isoPayInXML input xml string
   * @return base64 string generated
   */
  public static String generateBase64InputFromISOXMLPayload (String isoPayInXML) {

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
   * Payment initiation logic
   *
   * @return response that contains the wanted statement ID(s)
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload
   * @throws HandlerException custom exception for Handler class
   */
  public static String initPayment (String payInitPayload)
      throws XMLSecurityException, HandlerException {
    try {
      KeyStore clientStore = KeyStore.getInstance("PKCS12");
      clientStore.load(new FileInputStream(HandlerConstant.sslCertFilePath),
          HandlerConstant.certPwd.toCharArray());
      KeyManagerFactory kmf = KeyManagerFactory
          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(clientStore, HandlerConstant.certPwd.toCharArray());
      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
      sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
      HttpsURLConnection
          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());
      Client client = new Client(new URLConnectionClientHandler(
          new HttpURLConnectionFactory() {
            Proxy proxy = null;

            public HttpURLConnection getHttpURLConnection(URL url)
                throws IOException {
              if (proxy == null && !proxyURL.isEmpty()) {
                proxy = new Proxy(Proxy.Type.HTTP,
                    new InetSocketAddress(HandlerConstant.proxyURL, 8080));
              } else {
                proxy = Proxy.NO_PROXY;
              }
              return (HttpURLConnection) url.openConnection(proxy);
            }
          }), new DefaultClientConfig());
      WebResource webResource = client.resource(HandlerConstant.payInitURL)
          .queryParam("client_id", HandlerConstant.clientID);
      Builder builder = webResource.type(MediaType.APPLICATION_XML);
      builder.header(HttpHeaders.AUTHORIZATION,
          "Bearer " + HandlerConstant.oAuthToken); // TODO: How can we store the oAuthToken obtained from authentication. suggested HashMap...
      builder.header("payloadType",
          "urn:iso:std:iso:20022:tech:xsd:pain.001.001.03");
      String payInitPayload_SignedEncrypted = signAndEncryptXML(payInitPayload);
      ClientResponse clientResponse = builder
          .post(ClientResponse.class, payInitPayload_SignedEncrypted);
      return clientResponse.getEntity(String.class);
    } catch (IOException | CertificateException | UnrecoverableKeyException |
        NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Balance inquiry logic
   *
   * @param balanceInquiryPayload request body in xml
   * @return response xml that contains the balance for the
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload
   * @throws HandlerException custom exception for Handler class
   */
  public static String checkBalance (String balanceInquiryPayload)
      throws XMLSecurityException, HandlerException {

    // TODO: check if this function body follows the body of initPayment() or not, since it follows 6.2 Payment Inquiry but there is no sample code for that
    try {
      KeyStore clientStore = KeyStore.getInstance("PKCS12");
      clientStore
          .load(new FileInputStream(HandlerConstant.sslCertFilePath),
              HandlerConstant.certPwd.toCharArray());
      KeyManagerFactory kmf = KeyManagerFactory
          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(clientStore, HandlerConstant.certPwd.toCharArray());
      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
      sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
      HttpsURLConnection
          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());
      Client client = new Client(new URLConnectionClientHandler(
          new HttpURLConnectionFactory() {
            Proxy proxy = new Proxy(Proxy.Type.HTTP,
                new InetSocketAddress(HandlerConstant.proxyURL, 8080));

            public HttpURLConnection getHttpURLConnection(URL url)
                throws IOException {
              return (HttpURLConnection) url.openConnection(proxy);
            }
          }), new DefaultClientConfig());
      WebResource webResource = client.resource(HandlerConstant.balanceInquiryUrl_UAT)
          .queryParam("client_id", HandlerConstant.clientID);
      Builder builder = webResource.accept(MediaType.APPLICATION_OCTET_STREAM)
          .accept(MediaType.APPLICATION_XML);
      builder.header(HttpHeaders.AUTHORIZATION,
          "Bearer " + HandlerConstant.oAuthToken);
      String balanceInquiryPayload_SignedEncrypted = signAndEncryptXML(
          balanceInquiryPayload);
      ClientResponse clientResponse = builder.post(ClientResponse.class,
              balanceInquiryPayload_SignedEncrypted);
      return clientResponse.getEntity(String.class);
    } catch (IOException | CertificateException | NoSuchAlgorithmException |
        UnrecoverableKeyException | KeyStoreException | KeyManagementException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Statement retrieval logic
   *
   * @param statementRetrievalPayload request body in xml
   * @return the Account Statement file in the required format: SWIFT MT940, or
   *         ISO XML camt.053.001.02 or SWIFT MT942 or ISO XML camt.052.001.02.
   *         If the request is rejected due to validation errors or data issues,
   *         the response follows a custom XML format.
   * @throws XMLSecurityException if an unexpected exception occurs while signing
   *                              the auth payload or encrypting the payload
   * @throws HandlerException custom exception for Handler class
   */
  public static InputStream retrieveStatement (String statementRetrievalPayload)
      throws XMLSecurityException, HandlerException {
    try {
      KeyStore clientStore = KeyStore.getInstance("PKCS12");
      clientStore
          .load(new FileInputStream(HandlerConstant.sslCertFilePath),
              HandlerConstant.certPwd.toCharArray());
      KeyManagerFactory kmf = KeyManagerFactory
          .getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(clientStore, HandlerConstant.certPwd.toCharArray());
      SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
      sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
      HttpsURLConnection
          .setDefaultSSLSocketFactory(sslContext.getSocketFactory());
      Client client = new Client(new URLConnectionClientHandler(
          new HttpURLConnectionFactory() {
            Proxy proxy = new Proxy(Proxy.Type.HTTP,
                new InetSocketAddress(HandlerConstant.proxyURL, 8080));

            public HttpURLConnection getHttpURLConnection(URL url)
                throws IOException {
              return (HttpURLConnection) url.openConnection(proxy);
            }
          }), new DefaultClientConfig());
      WebResource webResource = client.resource(HandlerConstant.statementRetUrl)
          .queryParam("client_id", HandlerConstant.clientID);
      Builder builder = webResource.accept(MediaType.APPLICATION_OCTET_STREAM)
          .accept(MediaType.APPLICATION_XML);
      builder.header(HttpHeaders.AUTHORIZATION,
          "Bearer " + HandlerConstant.oAuthToken);
      String statementRetrievalPayload_SignedEncrypted = signAndEncryptXML(
          statementRetrievalPayload);
      ClientResponse clientResponse = builder.type(MediaType.APPLICATION_XML)
          .post(ClientResponse.class, statementRetrievalPayload_SignedEncrypted);
      return clientResponse.getEntityInputStream();
    } catch (IOException | CertificateException | NoSuchAlgorithmException |
        UnrecoverableKeyException | KeyStoreException | KeyManagementException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /* Response Retrieval Logic */

//  Statement Retrieval Instructions
//      1.	Get the Cipher instance of TripleDES/CBC/NoPadding
//      2.	Get the instance of IvParameterSpec with the first 8 bytes of the encrypted attachment (Attachment MTOM response)
//      3.	Set the Cipher instance as decrypt mode with the decryption key and IvParameterSpec instance.
//      4.	Decrypt the encrypted attachment (excluding first 8 bytes) using the cipher instance.
//      5.	Use  decrypted response (from #4) and decrypt using base64 to get the decrypted statement file.
//
//  Decryption Key retrieval logic:
//      1.	Get the attachment decryption key from xPath //statementRetrievalResponse//attachmentDecryptionKey
//      2.	Get the instance of DESedeKeySpec with the Base64 decoded of attachment decrypted key.
//      3.	Get the instance of SecretKeyFactory with DESede
//      4.	Get the decryption key using SecretKeyFactory instance with DESedeKeySpec instance

  /* Webservice Logic */

  /**
   *
   *
   * @return
   */
  public static ResponseEntity<?> ss() {
    ResponseEntity<?> responseEntity = restTemplate
        .exchange(uri, httpMethod, requestEntity, byte[].class);
    try {
      ResponseEntity<?> responseEntity = restTemplate
          .exchange(uri, httpMethod, requestEntity, byte[].class);
      response.put("HDR", responseEntity.getHeaders());
      response.put("STATUS", responseEntity.getStatusCode());
      response.put("BODY", responseEntity.getBody());
    } catch (HttpStatusCodeException e) { // TODO: why is this inheriting from java.lang.throwable but still raises an error
      response.put("HDR", e.getResponseHeaders());
      response.put("STATUS", e.getStatusCode());
      response.put("BODY", e.getResponseBodyAsByteArray());
    }
    return responseEntity;
  }

  /**
   * Response extraction
   *
   * @param response
   * @param path
   * @return
   * @throws MessagingException
   * @throws IOException
   */
  private String extractMTOM(byte[] response, Path path) throws MessagingException, IOException {
//    response= responseEntity.getBody()
//    path= attachment file location
    String responseStatRetXMLStr = "";
    MimeMultipart mp = new MimeMultipart(new ByteArrayDataSource(response,
        org.springframework.http.MediaType.TEXT_XML_VALUE));
    for (int i = 0; i < mp.getCount(); i++) {
      BodyPart bodyPart = mp.getBodyPart(i);
      String contentType = bodyPart.getContentType();
      Logger.getLogger(Handler.class.getName()).info("ContentType==>" + contentType)
      Logger.getLogger(Handler.class.getName()).info("Content==>" + bodyPart.getContent());

      //TODO
      if(bodyPart.isMimeType("text/xml") || bodyPart.isMimeType("application/xml")) {// if text/xml
        if(SharedByteArrayInputStream.class.equals(bodyPart.getContent().getClass())) {
          responseStatRetXMLStr = IOUtils.toString((SharedByteArrayInputStream)bodyPart.getContent(), StandardCharsets.UTF_8);
        } else {
          responseStatRetXMLStr = (String)bodyPart.getContent();
        }
        continue;
      } else { //if application/octet-stream or application/xop+xml
        if(String.class.equals(bodyPart.getContent().getClass())) {
          Files.write(path, ((String)bodyPart.getContent()).getBytes());
        } else {
          ByteArrayInputStream bais = (ByteArrayInputStream)bodyPart.getContent();
          Files.copy(bais, path);
        }
      }
    }

    return responseStatRetXMLStr;
  }

  /**
   * Attachment Decryption Logic
   *
   * @param decryptionKey
   * @param input
   * @return
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws NoSuchPaddingException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  private byte[] des3DecodeCBC(String decryptionKey, byte[] input)
      throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
      NoSuchPaddingException, InvalidAlgorithmParameterException,
      IllegalBlockSizeException, BadPaddingException {

    // attachment byte array from MIME response
    int ivLen = 8;
    byte[] keyiv = new byte[ivLen];
    for(int i=0 ; i<ivLen ; i++) {
      keyiv[i] = input[i];
    }

    int dataLen = input.length-ivLen;
    byte[] data = new byte[dataLen];
    for (int i=0 ; i<dataLen ; i++) {
      data[i] = input[i+ivLen];
    }

    DESedeKeySpec spec = new DESedeKeySpec(Base64.decodeBase64(decryptionKey));
    SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
    Key deskey = keyfactory.generateSecret(spec);

    Cipher cipher = Cipher.getInstance("TripleDES/CBC/NoPadding");
    IvParameterSpec ips = new IvParameterSpec(keyiv);
    cipher.init(Cipher.DECRYPT_MODE, deskey, ips);

    byte[] bout = cipher.doFinal(data);

    return Base64.decodeBase64(bout);
  }

}
