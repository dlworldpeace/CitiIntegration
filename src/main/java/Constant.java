package main.java;

public class Constant {

  /* Inputs to the UAT Keys and Certificates */

  public static final String KEYSTORE_FILEPATH_UAT =
      "src/main/resources/key/deskera/UAT/deskera_uat.p12";
  public static final String KEYSTORE_PASSWORD_UAT = "clientpass";
  public static final String KEYSTORE_ALIAS_UAT = "1";
  public static final String CITI_PUBLIC_KEY_PATH_UAT =
      "src/main/resources/key/citi/citi_encryption_uat.pem";
  public static final String CITI_SIGNING_CERT_PATH_UAT =
      "src/main/resources/key/citi/citi_signature_uat.pem";
  public static final String DESKERA_CLIENT_ID_FILE_PATH_UAT =
      "src/main/resources/key/deskera/UAT/deskera_client_id_uat.txt";
  public static final String DESKERA_SECRET_KEY_FILE_PATH_UAT =
      "src/main/resources/key/deskera/UAT/deskera_secret_key_uat.txt";
  public static final String DESKERA_SSL_CERT_FILE_PATH_UAT =
      "src/main/resources/key/deskera/UAT/deskera_ssl_uat.p12";
  public static final String DESKERA_SSL_CERT_PWD_UAT = "sslpass";
  public static final String CITI_SSL_CERT_FILE_PATH_UAT =
      "src/main/resources/key/citi/citi_ssl_uat.jks";
  public static final String CITI_SSL_CERT_PWD_UAT = "citissl";

  /* Inputs to the PROD Keys and Certificates */

  public static final String KEYSTORE_FILEPATH_PROD =
      "src/main/resources/key/deskera/PROD/deskera_prod.p12";
  public static final String KEYSTORE_PASSWORD_PROD = "clientpass";
  public static final String KEYSTORE_ALIAS_PROD = "1";
  public static final String CITI_PUBLIC_KEY_PATH_PROD =
      "src/main/resources/key/citi/citi_encryption_prod.pem";
  public static final String CITI_SIGNING_CERT_PATH_PROD =
      "src/main/resources/key/citi/citi_signature_prod.pem";
  public static final String DESKERA_CLIENT_ID_FILE_PATH_PROD =
      "src/main/resources/key/deskera/PROD/deskera_client_id_prod.txt";
  public static final String DESKERA_SECRET_KEY_FILE_PATH_PROD =
      "src/main/resources/key/deskera/PROD/deskera_secret_key_prod.txt";
  public static final String DESKERA_SSL_CERT_FILE_PATH_PROD =
      "src/main/resources/key/deskera/PROD/deskera_ssl_prod.p12";
  public static final String DESKERA_SSL_CERT_PWD_PROD = "sslpass";
  public static final String CITI_SSL_CERT_FILE_PATH_PROD =
      "src/main/resources/key/citi/citi_ssl_prod.jks";
  public static final String CITI_SSL_CERT_PWD_PROD = "citissl";

  /* Inputs to the Parsing Response Logic */

  public static final String TYPE_AUTH = "";
  public static final String TYPE_PAY_INIT = "BASE64";
  public static final String TAG_NAME_AUTH = "//access_token/text()";
  public static final String TAG_NAME_PAY_INIT = "//Response/text()";

  /* Inputs to API Headers */

  public static final String PAYMENT_TYPE_HEADER = "payloadType";
  public static final String OUTGOING_PAYMENT_TYPE =
      "urn:iso:std:iso:20022:tech:xsd:pain.001.001.03";
  public static final String PAY_ENHANCED_STATUS_SAMPLE_ENDTOENDID = "SGD123";

  /* Inputs to Response Parsing Logic */

  public static final String PAIN001_CLASS_PATH = "deskera.fintech.pain001";
  public static final String PAIN002_CLASS_PATH = "deskera.fintech.pain002";
  public static final String CAMT052_CLASS_PATH = "deskera.fintech.camt052";
  public static final String CAMT053_CLASS_PATH = "deskera.fintech.camt053";
  public static final String OAUTH_CLASS_PATH = "deskera.fintech.oauth";
  public static final String PAY_INIT_CLASS_PATH = "deskera.fintech.payinit";
  public static final String STAT_INIT_CLASS_PATH = "deskera.fintech.statinit";
  public static final String STAT_RET_CLASS_PATH = "deskera.fintech.statret";
  public static final String DESKERA_PAIN_CLASS_PATH = "main.java.payinit";
  public static final String DESKERA_STAT_CLASS_PATH = "main.java.statement";

  /* URLs for both UAT and PROD */

  public static final String OAUTH_URL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/authenticationservices/"
          + "v1/oauth/token";
  public static final String OAUTH_URL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/authenticationservices/v1/"
          + "oauth/token";
  public static final String PAY_INIT_URL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/paymentservices/v1/"
          + "payment/initiation?";
  public static final String PAY_INIT_URL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/paymentservices/v1/payment/"
          + "initiation?";
  public static final String PAY_ENHANCED_STATUS_URL_UAT =
      "https://tts.sandbox.apib2b.citi.com/citiconnect/sb/paymentservices/v1/"
          + "payment/enhancedinquiry?";
  public static final String PAY_ENHANCED_STATUS_URL_PROD =
      "https://tts.apib2b.citi.com/citiconnect/prod/paymentservices/v1/payment/"
          + "enhancedinquiry?";
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
