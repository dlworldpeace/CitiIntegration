package main.java;

public class HandlerConstant {

  /* Inputs to the Encryption Logic */
  public static final String keyStoreFilePath = "src/main/resources/key/deskera/deskera.p12";
  public static final String keyStorePwd = "clientpass";
  public static final String clientSignKeyAlias = "1";
  public static final String citiEncryptKeyAlias = "CitiEncryptPublicKey";

  /* Inputs to the Decryption Logic */
  public static final String clientDecryptKeyAlias = "1";
  public static final String citiVerifyKeyAlias = "CitiSignaturePublicKey";

  /* Inputs to the Parsing Response Logic */
  public static final String authType = "";
  public static final String paymentType = "BASE64";
  public static final String tagName_Auth = "//access_token/text()";
  public static final String tagName_PaymentInit = "//Response/text()";

  /* Sample Authentication Payload */
  public static final String oAuthPayload_CCF =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
          + "<oAuthToken xmlns=\"http://com.citi.citiconnect/services/types/oauthtoken/v1\">\n"
          + "<grantType>client_credentials</grantType>\n"
          + "<scope>/authenticationservices/v1</scope>\n"
          + "<sourceApplication>CCF</sourceApplication>\n"
          + "</oAuthToken>";
  public static final String oAuthPayload_FAST =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
          + "<oAuthToken xmlns=\"http://com.citi.citiconnect/services/types/oauthtoken/v1\">\n"
          + "<grantType>client_credentials</grantType>\n"
          + "<scope>/authenticationservices/v1</scope>\n"
          + "</oAuthToken>";

  /* Inputs to the Authentication API Calling Logic */
  public static final String sslCertFilePath = "C:\\API\\Cert\\SSL.p12"; //SSLcert.pem
  public static final String certPwd = "pass123"; // where do we get this from?
  public static final String proxyURL = "webproxy.abc.net"; // what is this?
  public static final String oAuthURL_UAT = "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/authenticationservices/v1/oauth/token";
  public static final String oAuthURL_PROD = "https://tts.apib2b.citi.com/citiconnect/prod/authenticationservices/v1/oauth/token";
  public static final String clientID  = "9a9069d1-ed93-4d40-8b60-1e56a53899df";
  public static final String clientSecretKey = "F5yR7jQ8iN6tU7xQ5sX8rQ8oP3lY0rJ8tQ8vO6hI7eE4rA1nS6";

  /* Sample Payment Initiation Payload */
  public static final String samplePaymentPayload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      + "<Request><paymentBase64>--Base64EncodedISOPaymentXML--</paymentBase64></Request>";

  /* Inputs to the Payment Initiation API Calling Logic */
  public static final String samplePayInitPayload =
      "";
  public static final String payInitURL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/paymentservices/v1/"
          + "payment/initiation?client_id=<%s>"; // <%s> = API Client ID shared
  public static final String payInitURL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/paymentservices/v1/payment/"
          + "initiation?client_id=<%s>"; // <%s> = API Client ID shared

//  public static final String sslCertFilePath = "C:\\API\\Cert\\SSL.p12";
//  public static final String certPwd = "pass123";
//  public static final String proxyURL = "webproxy.abc.net";
//  public static final String clientID = "9a9069d1-ed93-4d40-8b60-1e56a53899df";
//  public static final String oAuthToken;

  /* Inputs to the Balance Inquiry API Calling Logic */
  public static final String sampleBalanceInquiryPayload =
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
          + "<balanceInquiryRequest xmlns=\"http://com.citi.citiconnect/services/types/inquiries/balance/v1\">\n"
          + "  <accountNumber>12345678</accountNumber>\n"
          + "  <branchNumber>600</branchNumber>\n"
          + "  <baseCurrency>USD</baseCurrency>\n"
          + "  <accountCurrency>USD</accountCurrency>\n"
          + "  <fromDate>2017-04-01</fromDate>\n"
          + "  <toDate>2017-04-30</toDate>\n"
          + "</balanceInquiryRequest>\n";
  public static final String balanceInquiryUrl_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/accountstatementservices"
          + "/v1/balance/inquiry?client_id=<%s>"; // <%s> = API Client ID shared
  public static final String balanceInquiryUrl_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "balance/inquiry?client_id=<%s>"; // <%s> = API Client ID shared

  /* Inputs to the Statement Retrieval API Calling Logic */
  public static final String sampleStatementRetPayload =
      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
          + "<statementRetrievalRequest xmlns=\"http://com.citi.citiconnect/services/types/attachments/v1\">\n"
          + "\t<statementId>ABC12312312</statementId>\n"
          + "</statementRetrievalRequest>";
  public static final String statementRetUrl_UAT = "https://sit.api.citiconnect.citigroup.com/citidirect/uat/payments/v2/statement/retrieval";
  public static final String statementRetUrl_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "statement/retrieval?client_id=<%s>"; // <%s> = API Client ID shared

//  public static final String sslCertFilePath = "C:\\API\\Cert\\SSL.p12"
//  public static final String certPwd = "pass123"
//  public static final String proxyURL = "webproxy.abc.net"
//  public static final String clientID = "9a9069d1-ed93-4d40-8b60-1e56a53899df";
//  public static final String oAuthToken;
}
