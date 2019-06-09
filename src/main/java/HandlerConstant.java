package main.java;

public class HandlerConstant {

  /* Inputs to the Encryption Logic */

  public static final String keyStoreFilePath =
      "src/main/resources/key/deskera/deskera.p12";
  public static final String keyStorePwd = "clientpass";
  public static final String clientSignKeyAlias = "1";
  public static final String citiEncryptKeyAlias = "CitiEncryptPublicKey";

  /* Inputs to the Decryption Logic */

  public static final String clientDecryptKeyAlias = "1";
  public static final String citiVerifyKeyAlias = "CitiSignaturePublicKey";

  /* Inputs to the Parsing Response Logic */

  public static final String type_Auth = "";
  public static final String type_PayInit = "BASE64";
  public static final String tagName_Auth = "//access_token/text()";
  public static final String tagName_PayInit = "//Response/text()";

  /* Inputs to APIs Calling Logic */

  public static final String deskeraSSLCertFilePath =
      "src/main/resources/key/deskera/deskera_ssl.p12";
  public static final String deskeraSSLCertPwd = "sslpass";
  public static final String citiSSLCertFilePath =
      "src/main/resources/key/citi/citi_ssl_uat.jks";
  public static final String citiSSLCertPwd = "citissl";
  public static final String proxyURL = ""; // what is this? Guess if it is intranet proxy
  public static final String paymentTypeHeader = "payloadType";
  public static final String outgoingPaymentType =
      "urn:iso:std:iso:20022:tech:xsd:pain.001.001.03";

  /* URLs for both UAT and PROD */

  public static final String oAuthURL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/authenticationservices/"
          + "v1/oauth/token";
  public static final String oAuthURL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/authenticationservices/v1/"
          + "oauth/token";
  public static final String payInitURL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/paymentservices/v1/"
          + "payment/initiation?";
  public static final String payInitURL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/paymentservices/v1/payment/"
          + "initiation?";
  public static final String balanceInquiryUrl_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/accountstatementservices"
          + "/v1/balance/inquiry?";
  public static final String balanceInquiryUrl_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "balance/inquiry?";
  public static final String statementInitUrl_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/accountstatementservices/"
          + "v1/statement/initiation?";
  public static final String statementInitUrl_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "statement/initiation?";
  public static final String statementRetUrl_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/accountstatementservices/"
          + "v1/statement/retrieval?";
  public static final String statementRetUrl_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "statement/retrieval?";
}
