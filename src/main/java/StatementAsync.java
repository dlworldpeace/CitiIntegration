package main.java;

import static main.java.Constant.KEYSTORE_FILEPATH_PROD;
import static main.java.Constant.KEYSTORE_PASSWORD_PROD;
import static main.java.Handler.getClientId;
import static main.java.Handler.getSecretKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.*;
import main.java.Handler.PaymentType;

public class StatementAsync {

  /* SQL Schema
  CREATE TABLE Statements (
    id INT AUTO_INCREMENT PRIMARY KEY,
    account_number VARCHAR(30) NOT NULL,
    from_date DATE NOT NULL,
    to_date DATE NOT NULL,
    statement_id VARCHAR(30) NOT NULL,
    retrieve_status BOOLEAN DEFAULT NULL,
    response varchar(255) DEFAULT NULL
  ) AUTO_INCREMENT = 1 ;

  INSERT INTO Statements (account_number, from_date, to_date, statement_id, retrieve_status, response)
  VALUES ('865828039', '2019-07-20', '2019-07-21', '207432286', false, 'some error response...'); */

  public static void main(String[] args) {

    try {
      // create a citi connection
      Handler handler = new Handler();
      handler.loadKeystore(KEYSTORE_FILEPATH_PROD, KEYSTORE_PASSWORD_PROD);
      String clientId = getClientId();
      String secretKey = getSecretKey();
      handler.requestOAuth(clientId, secretKey, PaymentType.DFT);

      // initiate a statement for retrieving it the next day
      String accountNumber = "123456789";
      String fromDate = "2019-07-21";
      String toDate = "2019-07-22";
      final String strInitStat = new String(Files.readAllBytes(Paths.get(
          "src/test/resources/sample/StatementInitiation/CAMTorSWIFT/XML Request/"
              + "StatementInitiationRequest_CAMT_053_001_02_Plain_Format.txt")))
          .replace("account_number", accountNumber)
          .replace("from_date", fromDate)
          .replace("to_date", toDate);
      final String statementId = handler.initiateStatement(clientId, strInitStat);

      // create a mysql database connection
      String myDriver = "org.gjt.mm.mysql.Driver";
      String myUrl = "jdbc:mysql://localhost/test";
      Class.forName(myDriver);
      Connection conn = DriverManager.getConnection(myUrl, "root", "mysql");
      Statement st = conn.createStatement();

      // if no HandlerException caused by server error response, proceed to insert a new entry
      st.executeUpdate(String.format(
          "INSERT INTO Statements (account_number, from_date, to_date, statement_id) VALUES ('%s', '%s', '%s', '%s'); ",
          accountNumber, fromDate, toDate, statementId));

      conn.close();
    } catch (HandlerException e) {
      System.err.println("Unable to initiate a statement!");
      System.err.println(e.getMessage());
    } catch (IOException | SQLException | ClassNotFoundException e) {
      System.err.println("Got an exception!");
      System.err.println(e.getMessage());
    }
  }

}