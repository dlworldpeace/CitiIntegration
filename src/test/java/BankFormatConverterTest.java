package test.java;

import static main.java.BankFormatConverter.convertCAMT053ToDeskeraStatement;
import static main.java.BankFormatConverter.convertJsonToPAIN001XML;
import static main.java.BankFormatConverter.createPayInitDocumentInstance;
import static main.java.BankFormatConverter.readCAMT052ToJson;
import static main.java.BankFormatConverter.readCAMT053ToJson;
import static main.java.BankFormatConverter.readDeskeraPaInXMLToDeskeraPaInJson;
import static main.java.BankFormatConverter.readJsonToDeskeraPaInElement;
import static main.java.Constant.CAMT053_CLASS_PATH;
import static main.java.Constant.DESKERA_STAT_CLASS_PATH;
import static main.java.Constant.PAIN001_CLASS_PATH;
import static org.custommonkey.xmlunit.XMLAssert.assertXMLEqual;

import deskera.fintech.pain001.Document;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConfigurationException;
import junit.framework.TestCase;
import main.java.BankFormatConverter;
import main.java.BankFormatConverterException;
import main.java.statement.DeskeraStatement;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.xml.sax.SAXException;

@RunWith(JUnit4.class)
public class BankFormatConverterTest extends TestCase {

  private final static String EMPTY_STRING = "";
  private final static String WHITE_SPACE = " ";
  private final static String SOME_XML = "<hi>123</hi>";

  @Test
  public void readXMLToElement_JAXBElementGeneratedCorrectly ()
      throws DatatypeConfigurationException, BankFormatConverterException,
      IOException {

    deskera.fintech.pain001.Document document = createPayInitDocumentInstance();
    JAXBElement<Document> documentElement =
        (new deskera.fintech.pain001.ObjectFactory()).createDocument(document);

    final String payloadSample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_ISOXMLPlain.txt")));
    BankFormatConverter<Document> converter =
        new BankFormatConverter<>(PAIN001_CLASS_PATH);
    JAXBElement<deskera.fintech.pain001.Document> documentMarshaled =
        converter.readXMLToElement(payloadSample);

    // TODO use assertEquals to compare all the contents within the two objects
//    assertEquals(documentElement, documentMarshaled);
  }

  @Test
  public void readCAMT053ToJson_sampleCAMT053Sample_readSuccess ()
      throws BankFormatConverterException, IOException {

    final String CAMT053Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "StatementRetrieval_CAMT_053_001_02_File.txt")));

    String res = readCAMT053ToJson(CAMT053Sample);

    System.out.println(res);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCAMT053ToJson_emptyStr_throwsHandlerException ()
      throws BankFormatConverterException {
    readCAMT053ToJson(EMPTY_STRING);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCAMT053ToJson_whiteSpace_throwsHandlerException ()
      throws BankFormatConverterException {
    readCAMT053ToJson(WHITE_SPACE);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCAMT053ToJson_invalidXML_throwsHandlerException ()
      throws BankFormatConverterException {
    readCAMT053ToJson(SOME_XML);
  }

  @Test
  public void readCAMT052ToJson_sampleCAMT052Sample_readSuccess ()
      throws BankFormatConverterException, IOException {

    final String CAMT052Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));

    String res = readCAMT052ToJson(CAMT052Sample);

    System.out.println(res);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCAMT052ToJson_emptyStr_throwsHandlerException ()
      throws BankFormatConverterException {
    readCAMT052ToJson(EMPTY_STRING);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCAMT052ToJson_whiteSpace_throwsHandlerException ()
      throws BankFormatConverterException {
    readCAMT052ToJson(WHITE_SPACE);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCAMT052ToJson_invalidXML_throwsHandlerException ()
      throws BankFormatConverterException {
    readCAMT052ToJson(SOME_XML);
  }

  @Test
  public void convertCAMT053ToDeskeraStatement_sampleCAMT053Sample_success ()
      throws IOException, BankFormatConverterException {

    final String CAMT053Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "StatementRetrieval_CAMT_053_001_02_File.txt")));
    BankFormatConverter<deskera.fintech.camt053.Document>
        docConverter = new BankFormatConverter<>(CAMT053_CLASS_PATH);
    JAXBElement<deskera.fintech.camt053.Document> documentElement =
        docConverter.readXMLToElement(CAMT053Sample);
    JAXBElement<DeskeraStatement> stmtElement =
        convertCAMT053ToDeskeraStatement(documentElement);
    BankFormatConverter<DeskeraStatement> statConverter =
        new BankFormatConverter<>(DESKERA_STAT_CLASS_PATH);
    System.out.println(statConverter.writeElementToJson(stmtElement));
  }

  @Test
  public void readDeskeraPaInXMLToDeskeraPaInJson_success ()
      throws IOException, BankFormatConverterException {

    final String deskeraPaInSampleXML = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "JSON Request/DeskeraFastPayInit_XML.txt")));
    System.out.println(readDeskeraPaInXMLToDeskeraPaInJson(deskeraPaInSampleXML));
  }

  @Test
  public void readJsonToDeskeraPaInElement_success ()
      throws IOException, BankFormatConverterException {

    final String deskeraPaInSampleJson = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "JSON Request/DeskeraFastPayInit_Json.txt")));
    readJsonToDeskeraPaInElement(deskeraPaInSampleJson);
  }

  @Test
  public void convertFASTPayJsonToPAIN001XML_success ()
      throws BankFormatConverterException, IOException, SAXException {

    final String deskeraPaInSampleJson = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "JSON Request/DeskeraFastPayInit_Json.txt")));
    final String PAIN001Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "XML Request/DeskeraFastISOXML.txt")));

    assertXMLEqual(PAIN001Sample, convertJsonToPAIN001XML(deskeraPaInSampleJson));
  }

  @Test
  public void convertDFTJsonToPAIN001XML_success ()
      throws BankFormatConverterException, IOException, SAXException {

    final String deskeraPaInSampleJson = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "JSON Request/DeskeraDFTinit_Json.txt")));
    final String PAIN001Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_ISOXMLPlain_DFT.txt")));

    assertXMLEqual(PAIN001Sample, convertJsonToPAIN001XML(deskeraPaInSampleJson));
  }
}