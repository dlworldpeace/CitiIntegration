package test.java;

import java.net.HttpURLConnection;
import java.net.URL;
import java.io.IOException;
import java.io.*;
import java.security.KeyStore;
import java.security.SecureRandom;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

public class AuthTest {

  private HttpURLConnection con;
  private String sslCertFilePath = "src/SSLcert.pem";
  private String certPwd = "pass123";

  private void connect() throws Exception {
    KeyStore clientStore = KeyStore.getInstance("PKCS12");
    clientStore.load(new FileInputStream(sslCertFilePath), certPwd.toCharArray());
    KeyManagerFactory kmf = KeyManagerFactory
        .getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(clientStore, certPwd.toCharArray());
    SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
    sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

    URL url = new URL("https://tts.sandbox.apib2b.citi.com/citiconnect/sb/"
        + "authenticationservices/v1/oauth/token");
    con = (HttpURLConnection) url.openConnection();
    con.setRequestMethod("POST");
    con.setDoOutput(true);
    con.setDoInput(true);
    con.setRequestProperty("Content-Type", "application/xml");
    con.setRequestProperty("Authorization", "Basic MTIzNGE1YjYtY2RlNy04ZjkwLTEy"
        + "Z2gtMzQ1aWo2Nzg5MDEyOmFiY2RlZmdoaWprbG1ub3A=");

    String writeBytes = ("<?xml version=\"1.0\" encoding=\"UTF-8\"?> "
        + "<oAuthToken xmlns=\"http://com.citi.citiconnect/services/types/oauthtoken/v1\">  "
        + "<grantType>client_credentials</grantType>  "
        + "<scope>/authenticationservices/v1</scope>  </oAuthToken>");
    con.setRequestProperty("Content-Length", String.valueOf(writeBytes.getBytes().length));
    OutputStream outWriteStream = con.getOutputStream();
    outWriteStream.write(writeBytes.getBytes());
    outWriteStream.flush();
    outWriteStream.close();
  }

  private void disconnect() {
    con.disconnect();
  }

  private void readResponse() throws IOException {
    int status = con.getResponseCode();

    Reader streamReader;

    if (status > 299) {
      streamReader = new InputStreamReader(con.getErrorStream());
    } else {
      streamReader = new InputStreamReader(con.getInputStream());
      BufferedReader in = new BufferedReader(streamReader);
      String inputLine;
      StringBuffer content = new StringBuffer();
      while ((inputLine = in.readLine()) != null) {
        content.append(inputLine);
      }
      System.out.println(inputLine);
      in.close();
    }
  }

  public static void main(String[] args) {
    AuthTest authTest = new AuthTest();

    try {
      authTest.connect();
      authTest.readResponse();
    } catch (Exception e) {
      e.printStackTrace();
    }
    authTest.disconnect();
  }
}