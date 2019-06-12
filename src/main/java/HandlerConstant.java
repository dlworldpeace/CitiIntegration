package main.java;

public class HandlerConstant {

  /* Inputs to the Encryption Logic */

  public static final String KEYSTORE_FILEPATH =
      "src/main/resources/key/deskera/deskera.p12";
  public static final String KEYSTORE_PASSWORD = "clientpass";
  public static final String KEYSTORE_ALIAS = "1";
  public static final String citiEncryptKeyAlias = "CitiEncryptPublicKey";

  /* Inputs to the Decryption Logic */

  public static final String clientDecryptKeyAlias = "1";
  public static final String citiVerifyKeyAlias = "CitiSignaturePublicKey";

  /* Inputs to the Parsing Response Logic */

  public static final String TYPE_AUTH = "";
  public static final String TYPE_PAY_INIT = "BASE64";
  public static final String TAG_NAME_AUTH = "//access_token/text()";
  public static final String TAG_NAME_PAY_INIT = "//Response/text()";

  /* Inputs to APIs Calling Logic */

  public static final String DESKERA_SSL_CERT_FILE_PATH =
      "src/main/resources/key/deskera/deskera_ssl.p12";
  public static final String DESKERA_SSL_CERT_PWD = "sslpass";
  public static final String CITI_SSL_CERT_FILE_PATH =
      "src/main/resources/key/citi/citi_ssl_uat.jks";
  public static final String CITI_SSL_CERT_PWD = "citissl";
  public static final String PROXY_URL = ""; // what is this? Guess if it is intranet proxy
  public static final String PAYMENT_TYPE_HEADER = "payloadType";
  public static final String OUTGOING_PAYMENT_TYPE =
      "urn:iso:std:iso:20022:tech:xsd:pain.001.001.03";

  /* Inputs to Response Parsing Logic */

  public static final String PAIN_CLASS_PATH = "main.java.pain";
  public static final String CAMT52_CLASS_PATH = "main.java.camt52";
  public static final String CAMT53_CLASS_PATH = "main.java.camt53";

  /* URLs for both UAT and PROD */

  public static final String O_AUTH_URL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/authenticationservices/"
          + "v1/oauth/token";
  public static final String O_AUTH_URL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/authenticationservices/v1/"
          + "oauth/token";
  public static final String PAY_INIT_URL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/paymentservices/v1/"
          + "payment/initiation?";
  public static final String PAY_INIT_URL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/paymentservices/v1/payment/"
          + "initiation?";
  public static final String BALANCE_INQUIRY_URL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/accountstatementservices"
          + "/v1/balance/inquiry?";
  public static final String BALANCE_INQUIRY_URL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "balance/inquiry?";
  public static final String STATEMENT_INIT_URL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/accountstatementservices/"
          + "v1/statement/initiation?";
  public static final String STATEMENT_INIT_URL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "statement/initiation?";
  public static final String STATEMENT_RET_URL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/accountstatementservices/"
          + "v1/statement/retrieval?";
  public static final String STATEMENT_RET_URL_MOCK =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/accountstatementservices/"
          + "v1/mock/statement/retrieval?";
  public static final String STATEMENT_RET_URL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/accountstatementservices/v1/"
          + "statement/retrieval?";
}
