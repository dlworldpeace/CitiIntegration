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

  /* Inputs to the Authentication API Calling Logic */

  public static final String sslCertFilePath = "src/main/resources/key/deskera/deskera_ssl.p12";
  public static final String sslCertPwd = "sslpass";
  public static final String proxyURL = ""; // what is this?
  public static final String oAuthURL_UAT = "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/authenticationservices/v1/oauth/token";
  public static final String oAuthURL_PROD = "https://tts.apib2b.citi.com/citiconnect/prod/authenticationservices/v1/oauth/token";

  /* Sample Payment Initiation Payload */

  public static final String samplePaymentPayload = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      + "<Request><paymentBase64>--Base64EncodedISOPaymentXML--</paymentBase64></Request>";

  /* Inputs to the Payment Initiation API Calling Logic */

  public static final String payInitURL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/paymentservices/v1/"
          + "payment/initiation?";
  public static final String payInitURL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/paymentservices/v1/payment/"
          + "initiation?";

  /* Inputs to the Balance Inquiry API Calling Logic */

  public static final String balanceInquiryUrl_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/accountstatementservices"
          + "/v1/balance/inquiry?";
  public static final String balanceInquiryUrl_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "balance/inquiry?";

  /* Inputs to the Statement Retrieval API Calling Logic */

  public static final String statementRetUrl_UAT = "https://sit.api.citiconnect.citigroup.com/citidirect/uat/payments/v2/statement/retrieval";
  public static final String statementRetUrl_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "statement/retrieval?";
}
