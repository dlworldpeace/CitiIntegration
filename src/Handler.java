import java.awt.PageAttributes.MediaType;
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
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.Builder;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
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
    } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
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
  public static Document convertXMLPayloadToDoc (String xmlPayload) throws HandlerException {
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
    } catch (CertificateNotYetValidException | CertificateExpiredException | KeyStoreException e) {
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
   * @throws XMLSecurityException if an unexpected exception occurs while signing the doc
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
    } catch (CertificateNotYetValidException | CertificateExpiredException | KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Encrypt the signed XML payload document
   *
   * @param signedXmlDoc signed XML document
   * @throws XMLEncryptionException
   * @throws HandlerException custom exception for Handler class
   */
  public static Document encryptSignedXMLPayloadDoc (Document signedXmlDoc,
      PublicKey publicEncryptKey) throws XMLEncryptionException, HandlerException {
    try{
    String jceAlgorithmName = "DESede";
    KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
    Key symmetricKey = keyGenerator.generateKey();
    String algorithmURI = XMLCipher.RSA_v1dot5;
    XMLCipher keyCipher = XMLCipher.getInstance(algorithmURI);
    keyCipher.init(XMLCipher.WRAP_MODE, publicEncryptKey);
    EncryptedKey encryptedKey = keyCipher.encryptKey(signedXmlDoc, symmetricKey);
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
  // TODO check what kind of string value is returned: XML?
  public static String convertDocToString (Document xmlDoc) throws HandlerException {
    TransformerFactory tf = TransformerFactory.newInstance();
    try {
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
    } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  // TODO remove this since we have 2 methods that do the same job by taking diff arguments
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
  public static X509Certificate getClientPublicDecryotKey () throws HandlerException {
    try {
      KeyStore ks = KeyStore.getInstance("JKS");
      X509Certificate decryptCert = (X509Certificate) ks
          .getCertificate(HandlerConstant.clientDecryptKeyAlias);
      decryptCert.checkValidity();
      return decryptCert;
    } catch (CertificateExpiredException | CertificateNotYetValidException | KeyStoreException e) {
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
   * @throws HandlerException custom exception for Handler class
   */
  public static void decryptEncryptedAndSignedXXML () throws HandlerException {
    xml.security.Init.init();

    Element docRoot = xmlDoc.getDocumentElement();
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
        .loadEncryptedData(xmlDoc, (Element) dataEL);
    EncryptedKey encryptedKey = cipher
        .loadEncryptedKey(xmlDoc, (Element) keyEL);
    if (encryptedData != null && encryptedKey != null) {
      String encAlgoURL = encryptedData.getEncryptionMethod().getAlgorithm();
      XMLCipher keyCipher = XMLCipher.getInstance();
      keyCipher.init(XMLCipher.UNWRAP_MODE, privateDecryptKey);
      Key encryptionKey = keyCipher.decryptKey(encryptedKey, encAlgoURL);
      cipher = XMLCipher.getInstance();
      cipher.init(XMLCipher.DECRYPT_MODE, encryptionKey);
      Document decryptedDoc = cipher.doFinal(xmlDoc, (Element) dataEL);
    }
    decryptedDoc.normalize();
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
    } catch (CertificateNotYetValidException | CertificateExpiredException | KeyStoreException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new HandlerException(e.getMessage());
    }
  }

  /**
   * Verifying the Signature of decrypted XML response Payload Document
   *
   * @throws HandlerException custom exception for Handler class
   */
  public static void verifySignatureofDecryptedXML () throws HandlerException {
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
            int enCodeCertLengthTobeValidated = signVerifyCert
                .getEncoded().length;
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
   * @return decrypted statement file as bytearray
   * @throws HandlerException custom exception for Handler class
   */
  public static byte[] decryptStatementFile () throws HandlerException {
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
    for (int i = 0; i < ivLen; i++) {
      keyiv[i] = encryptedStatementFile[i];
    }
    int dataLen = encryptedStatementFile.length - ivLen;
    byte[] data = new byte[dataLen];
    for (int i = 0; i < dataLen; i++) {
      data[i] = encryptedStatementFile[i + ivLen];
    }
    Key deskey;
    DESedeKeySpec spec = new DESedeKeySpec(Base64.decodeBase64(decryptionKey));
    SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
    deskey = keyfactory.generateSecret(spec);
    Cipher cipher = Cipher
        .getInstance("TripleDES/CBC/NoPadding");//PKCS5Padding NoPadding
    IvParameterSpec ips = new IvParameterSpec(keyiv);
    cipher.init(Cipher.DECRYPT_MODE, deskey, ips);
    byte[] bout = cipher.doFinal(data);
    return Base64.decodeBase64(bout);
  }

  /* Parsing Response Logic */

  /**
   * Parsing response to show error or valid message logic
   *
   * @param responseDoc document to be parsed
   * @throws HandlerException custom exception for Handler class
   */
  public static void handleResponse (Document responseDoc) throws HandlerException {
    XPath xpath = XPathFactory.newInstance().newXPath();

    String errorInResponse = "";
    Element docRoot = responseDoc.getDocumentElement();
    if (docRoot == null || docRoot.getNodeName() == null) {
      errorInResponse = "Response Message Doesn't have expected Information";
    } else {
      if (docRoot.getNodeName().equalsIgnoreCase("errormessage")) {
        StringBuffer errorReponseSB = new StringBuffer();

        String httpCodeTag = null, httpMessage = null, moreInformation = null;
        NodeList nodes = (NodeList) xpath.compile("//httpCode/text()")
            .evaluate(responseDoc, XPathConstants.NODESET);
        if (nodes != null && nodes.getLength() == 1) {
          httpCodeTag = "HTTP:" + nodes.item(0).getNodeValue();
        }

        try {
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
        response = nodes.item(0).getNodeValue();
      }
      if ("BASE64".equals(type)) {
        String response = new String(Base64.decodeBase64(response));
      }
    }
  }

  /**
   * Parsing MTOM Response (Parser for Statement Retrieval Response)
   *
   * @throws HandlerException custom exception for Handler class
   */
  public static void parseMTOPResponse () throws HandlerException {
    MimeMultipart mp = new MimeMultipart(
        new ByteArrayDataSource(response, MediaType.TEXT_XML));
    for (int i = 0; i < mp.getCount(); i++) {
      BodyPart bodyPart = mp.getBodyPart(i);
      String contentType = bodyPart.getContentType();
      logger.info("ContentTyp==>", contentType);
      if (bodyPart.isMimeType("text/xml")) {// if text/xml
        responseStatRetXMLStr = (String) bodyPart.getContent();
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
        byte[] encryptedStatementFile = buffer.toByteArray();
      }
    }
  }

  /* API Calling Logics */

  /**
   * Authentication Calling Logic: establish handshake through keys
   *
   * @return result of handshake
   * @throws HandlerException custom exception for Handler class
   */
  public static String authenticate () throws HandlerException {
    KeyStore clientStore = KeyStore.getInstance("PKCS12");
    clientStore
        .load(new FileInputStream(HandlerConstant.sslCertFilePath), HandlerConstant.certPwd.toCharArray());

    KeyManagerFactory kmf = KeyManagerFactory
        .getInstance(KeyManagerFactory.getDefaultAlgorithm());

    kmf.init(clientStore, HandlerConstant.certPwd.toCharArray());

    SSLContext sslContext = SSLContext.getInstance("TLSv1.2"); // What is TLSv1.2?
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
    WebResource webResource = client.resource(HandlerConstant.oAuthURL);
    Builder builder = webResource.type(MediaType.APPLICATION_XML);
    builder.header(HttpHeaders.AUTHORIZATION, "Basic " + Base64
        .encodeBase64String((clientID + ":" + HandlerConstant.clientSecret).getBytes())
        .replaceAll("(\\r|\\n)", ""));
    ClientResponse clientResponse = builder
        .post(ClientResponse.class, HandlerConstant.oAuthPayloadSignedEncrypted);
    return clientResponse.getEntity(String.class);
  }

  /**
   * Payment Initiation API: Generate Base64 Input Request from ISO XML Payload
   *
   * @return base64 string generated
   * @throws HandlerException custom exception for Handler class
   */
  public static String generateBase64InputFromISOXMLPayload () throws HandlerException {

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
   * Payment Initiation API: Calling Logic
   *
   * @return base64 string generated
   * @throws HandlerException custom exception for Handler class
   */
  public static String generateBase64InputFromISOXMLPayload () throws HandlerException {
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
    builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + HandlerConstant.oAuthToken);
    builder.header("payloadType",
        "urn:iso:std:iso:20022:tech:xsd:pain.001.001.03");
    ClientResponse clientResponse = builder
        .post(ClientResponse.class, payInitPayloadSignedEncrypted);
    return clientResponse.getEntity(String.class);
  }

  /**
   * Statement Retrieval API: Calling Logic
   *
   * @return response in a stream
   * @throws HandlerException custom exception for Handler class
   */
  public static InputStream retrieveStatement () throws HandlerException {
    KeyStore clientStore = KeyStore.getInstance("PKCS12");
    clientStore
        .load(new FileInputStream(HandlerConstant.sslCertFilePath), HandlerConstant.certPwd.toCharArray());
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
    WebResource webResource = client.resource(HandlerConstant.statmentRetUrl)
        .queryParam("client_id", HandlerConstant.clientID);
    Builder builder = webResource.accept(MediaType.APPLICATION_OCTET_STREAM)
        .accept(MediaType.APPLICATION_XML);
    builder.header(HttpHeaders.AUTHORIZATION, "Bearer " + HandlerConstant.oAuthToken);
    ClientResponse clientResponse = builder.type(MediaType.APPLICATION_XML)
        .post(ClientResponse.class, HandlerConstant.payloadSignedEncrypted);
    return clientResponse.getEntityInputStream();
  }

  public static void main(String[] args) {
    Handler.signXMLPayloadDoc();
  }

}
