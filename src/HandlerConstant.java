public class HandlerConstant {

  /* Inputs to the Encryption Logic */
  public static final String keyStoreFilePath = "C:\\API\\Cert\\ClientKeyStore.jks";
  public static final String keyStorePwd = "pass123";
  public static final String clientSignKeyAlias = "ClientSignaturePrivateKey";
  public static final String citiEncryptKeyAlias = "CitiEncryptPublicKey";

  /* Inputs to the Decryption Logic */
  public static final String clientDecryptKeyAlias = "ClientEncryptionPrivateKey";
  public static final String citiVerifyKeyAlias = "CitiSignaturePublicKey";

  /* Inputs to the Parsing Response Logic */
  public static final String authType = ""; // for Authentication
  public static final String paymentType = "BASE64"; // for Payment Initiation
  public static final String tagName = "//access_token/text()” for Authentication & "
      + "“//Response/text()” for Payment Initiation";

  /* Sample Authentication Payload */
  public static final String oAuthPayloadSignedEncrypted =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
          + "<oAuthToken xmlns=\"http://com.citi.citiconnect/services/types/oauthtoken/v1\">\n"
          + "<grantType>client_credentials</grantType>\n"
          + "<scope>/authenticationservices/v1</scope>\n"
          + "<sourceApplication>CCF</sourceApplication>\n"
          + "</oAuthToken>";

  /* Inputs to the Authentication API Calling Logic */
  public static final String sslCertFilePath = "C:\\API\\Cert\\SSL.p12"; //SSLcert.pem
  public static final String certPwd = "pass123"; // where do we get this from?
  public static final String proxyURL = "webproxy.abc.net"; // what is this?
  public static final String oAuthURL = "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/authenticationservices/v1/oauth/token";
  public static final String clientID  = "9a9069d1-ed93-4d40-8b60-1e56a53899df";
  public static final String clientSecret = "F5yR7jQ8iN6tU7xQ5sX8rQ8oP3lY0rJ8tQ8vO6hI7eE4rA1nS6";

  /* Sample Payment Initiation Payload */
  public static final String samplePaymentPayload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      + "<Request><paymentBase64>--Base64EncodedISOPaymentXML--</paymentBase64></Request>";

  //c)	Inputs to the Payment Initiation API Calling Logic

  /* Inputs to the Payment Initiation API Calling Logic */
  public static final String payInitPayloadSignedEncrypted
  public static final String sslCertFilePath = "C:\\API\\Cert\\SSL.p12";
  public static final String certPwd = "pass123";
  public static final String proxyURL = "webproxy.abc.net";
  public static final String payInitURL = "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/paymentservices/v1/payment/initiation";
  public static final String clientID = "9a9069d1-ed93-4d40-8b60-1e56a53899df";
  public static final String oAuthToken;

  /* Inputs to the Statement Retrieval API Calling Logic */
  public static final String payloadSignedEncrypted
  public static final String sslCertFilePath = "C:\\API\\Cert\\SSL.p12"
  public static final String certPwd = "pass123"
  public static final String proxyURL = "webproxy.abc.net"
  public static final String statmentRetUrl = "https://sit.api.citiconnect.citigroup.com/citidirect/uat/payments/v2/statement/retrieval";
  public static final String clientID = "9a9069d1-ed93-4d40-8b60-1e56a53899df";
  public static final String oAuthToken;
}
