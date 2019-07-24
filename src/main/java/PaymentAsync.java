package main.java;

import static main.java.Constant.KEYSTORE_FILEPATH_PROD;
import static main.java.Constant.KEYSTORE_PASSWORD_PROD;
import static main.java.Constant.PAIN002_CLASS_PATH;
import static main.java.Handler.getClientId;
import static main.java.Handler.getSecretKey;

import deskera.fintech.pain002.Document;
import deskera.fintech.pain002.TransactionIndividualStatus3Code;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import java.util.UUID;
import javax.xml.bind.JAXBElement;
import main.java.Handler.PaymentType;

public class PaymentAsync {

  /* SQL Schema
  CREATE TABLE bank_payments (
    id VARCHAR(50) PRIMARY KEY,
    end_to_end_id VARCHAR(50) UNIQUE NOT NULL,
    status VARCHAR(10) DEFAULT NULL,
    additional_info VARCHAR(255) DEFAULT NULL)

  INSERT INTO bank_payments (id, end_to_end_id)
  VALUES ('sdadu90870jnoi123nf0j0', 'ABC-0000')

  INSERT INTO bank_payments (id, end_to_end_id, status)
  VALUES ('sdadu90870jnoi123nf0j0', 'ABC-0000', 'ACCP')

  INSERT INTO bank_payments (id, end_to_end_id, status, additional_info)
  VALUES ('sdadu90870jnoi123nf0j0', 'ABC-0000', 'ACCP', '/00000000/Payment Accepted for Submission')

  SELECT end_to_end_id
  FROM bank_payments
  WHERE status <> 'RJCT' AND (
      status <> 'ACSP' OR
      ( additional_info NOT LIKE '%Accepted%' AND
        additional_info NOT LIKE '%Processed%' )) OR
      status IS NULL

  UPDATE bank_payments SET status = 'null', additional_info = 'null' WHERE id = 'sdadu90870jnoi123nf0j0'
  */

  public static void main(String[] args) {

    try {
      // create a citi connection
      Handler handler = new Handler();
      handler.loadKeystore(KEYSTORE_FILEPATH_PROD, KEYSTORE_PASSWORD_PROD);
      String clientId = getClientId();
      String secretKey = getSecretKey();
      handler.requestOAuth(clientId, secretKey, PaymentType.DFT);

      // create a mysql database connection TODO: replace this with your own connectivity settings
      String myDriver = "org.gjt.mm.mysql.Driver";
      String myUrl = "jdbc:mysql://localhost/test";
      Class.forName(myDriver);
      Connection conn = DriverManager.getConnection(myUrl, "root", "mysql");
      Statement st = conn.createStatement();

      // payment initiation logic
      String endToEndId = "ABC-0001"; // TODO: add your unique id generation logic here
      String strInitPay = new String(Files.readAllBytes(Paths.get(
          "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
              + "XML Request/PaymentInitRequest_ISOXMLPlain_DFT_Format.txt")))
          .replace("end_to_end_id", endToEndId);
      String resInitPay = handler.initiatePayment(clientId, strInitPay);

      BankFormatConverter<deskera.fintech.pain002.Document>
          converter = new BankFormatConverter<>(PAIN002_CLASS_PATH);
      JAXBElement<Document> documentElement = converter.readXmlToElement(resInitPay);
      TransactionIndividualStatus3Code status =
          documentElement.getValue().getCstmrPmtStsRpt().getOrgnlPmtInfAndSts()
          .get(0).getTxInfAndSts().get(0).getTxSts();
      List<String> additionalInfo = documentElement.getValue().getCstmrPmtStsRpt().getOrgnlPmtInfAndSts()
          .get(0).getTxInfAndSts().get(0).getStsRsnInf().get(0).getAddtlInf();

      String uuid = UUID.randomUUID().toString().replace("-", "");

      if (status == null && additionalInfo.isEmpty()) {
        st.executeUpdate(String.format(
            "INSERT INTO bank_payments (id, end_to_end_id) VALUES ('%s', '%s');",
            uuid, endToEndId));
      } else if (status == null) {
        st.executeUpdate(String.format(
            "INSERT INTO bank_payments (id, end_to_end_id, additional_info) VALUES ('%s', '%s', '%s');",
            uuid, endToEndId, String.join("", additionalInfo)));
      } else if (additionalInfo.isEmpty()) {
        st.executeUpdate(String.format(
            "INSERT INTO bank_payments (id, end_to_end_id, status) VALUES ('%s', '%s', '%s');",
            uuid, endToEndId, status));
      } else {
        st.executeUpdate(String.format(
            "INSERT INTO bank_payments (id, end_to_end_id, status, additional_info) VALUES ('%s', '%s', '%s', '%s');",
            uuid, endToEndId, status, String.join("", additionalInfo)));
      }

      // payment status inquiry logic
      String query = "SELECT end_to_end_id FROM bank_payments WHERE "
          + " status <> 'RJCT' AND ("
          + " status <> 'ACSP' OR"
          + " ( additional_info NOT LIKE '%Accepted%' AND"
          + "   additional_info NOT LIKE '%Processed%' )) OR"
          + " status IS NULL";
      ResultSet rs = st.executeQuery(query);

      while (rs.next()) {
        String _endToEndId = rs.getString("end_to_end_id");
        String resCheckPay = handler.checkPaymentStatus(clientId, _endToEndId);
        documentElement = converter.readXmlToElement(resCheckPay);
        status = documentElement.getValue().getCstmrPmtStsRpt().getOrgnlPmtInfAndSts()
                .get(0).getTxInfAndSts().get(0).getTxSts();
        additionalInfo = documentElement.getValue().getCstmrPmtStsRpt().getOrgnlPmtInfAndSts()
            .get(0).getTxInfAndSts().get(0).getStsRsnInf().get(0).getAddtlInf();

        if (status == null && additionalInfo.isEmpty()) {
          st.executeUpdate(String.format(
              "UPDATE bank_payments SET status = NULL , additional_info = NULL WHERE end_to_end_id = '%s'",
              _endToEndId));
        } else if (status == null) {
          st.executeUpdate(String.format(
              "UPDATE bank_payments SET status = NULL , additional_info = '%s' WHERE end_to_end_id = '%s'",
              String.join("", additionalInfo), _endToEndId));
        } else if (additionalInfo.isEmpty()) {
          st.executeUpdate(String.format(
              "UPDATE bank_payments SET status = '%s' , additional_info = NULL WHERE end_to_end_id = '%s'",
              status, _endToEndId));
        } else {
          st.executeUpdate(String.format(
              "UPDATE bank_payments SET status = '%s' , additional_info = '%s' WHERE end_to_end_id = '%s'",
              status, String.join("", additionalInfo), _endToEndId));
        }
      }

      st.close();
      conn.close();
    } catch (BankFormatConverterException | HandlerException e) {
      System.err.println("Unable to check payment status!");
      System.err.println(e.getMessage());
    } catch (IOException | SQLException | ClassNotFoundException e) {
      System.err.println("Got an exception!");
      System.err.println(e.getMessage());
    }
  }

}