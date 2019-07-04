package test.java;

import static main.java.BankFormatConverter.convertCamt053ToDeskeraStatement;
import static main.java.BankFormatConverter.convertJsonToPaIn001Xml;
import static main.java.BankFormatConverter.createPayInitDocumentInstance;
import static main.java.BankFormatConverter.readCamt052ToJson;
import static main.java.BankFormatConverter.readCamt053ToJson;
import static main.java.BankFormatConverter.readDeskeraPaInXmlToDeskeraPaInJson;
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

  private static final String EMPTY_STRING = "";
  private static final String WHITE_SPACE = " ";
  private static final String SOME_XML = "<hi>123</hi>";

  @Test
  public void readXmlToElement_jaxbElementGenerateCorrectly()
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
        converter.readXmlToElement(payloadSample);

    // TODO use assertEquals to compare all the contents within the two objects
    //assertEquals(documentElement, documentMarshaled);
  }

  @Test
  public void readCamt053ToJson_sampleCamt053Sample_readSuccess()
      throws BankFormatConverterException, IOException {

    final String camt053Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "StatementRetrieval_CAMT_053_001_02_File.txt")));

    String res = readCamt053ToJson(camt053Sample);

    System.out.println(res);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCamt053ToJson_emptyStr_throwsHandlerException()
      throws BankFormatConverterException {
    readCamt053ToJson(EMPTY_STRING);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCamt053ToJson_whiteSpace_throwsHandlerException()
      throws BankFormatConverterException {
    readCamt053ToJson(WHITE_SPACE);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCamt053ToJson_invalidXml_throwsHandlerException()
      throws BankFormatConverterException {
    readCamt053ToJson(SOME_XML);
  }

  @Test
  public void readCamt052ToJson_sampleCamt052Sample_readSuccess()
      throws BankFormatConverterException, IOException {

    final String camt052Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));

    String res = readCamt052ToJson(camt052Sample);

    System.out.println(res);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCamt052ToJson_emptyStr_throwsHandlerException()
      throws BankFormatConverterException {
    readCamt052ToJson(EMPTY_STRING);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCamt052ToJson_whiteSpace_throwsHandlerException()
      throws BankFormatConverterException {
    readCamt052ToJson(WHITE_SPACE);
  }

  @Test (expected = BankFormatConverterException.class)
  public void readCamt052ToJson_invalidXml_throwsHandlerException()
      throws BankFormatConverterException {
    readCamt052ToJson(SOME_XML);
  }

  @Test
  public void convertCamt053ToDeskeraStatement_sampleCamt053Sample_success()
      throws IOException, BankFormatConverterException {

    final String camt053Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "StatementRetrieval_CAMT_053_001_02_File.txt")));
    BankFormatConverter<deskera.fintech.camt053.Document>
        docConverter = new BankFormatConverter<>(CAMT053_CLASS_PATH);
    JAXBElement<deskera.fintech.camt053.Document> documentElement =
        docConverter.readXmlToElement(camt053Sample);
    JAXBElement<DeskeraStatement> stmtElement =
        convertCamt053ToDeskeraStatement(documentElement);
    BankFormatConverter<DeskeraStatement> statConverter =
        new BankFormatConverter<>(DESKERA_STAT_CLASS_PATH);
    System.out.println(statConverter.writeElementToJson(stmtElement));
  }

  @Test
  public void readDeskeraPaInXmlToDeskeraPaInJson_success()
      throws IOException, BankFormatConverterException {

    final String deskeraPaInSampleXml = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "JSON Request/DeskeraFastPayInit_XML.txt")));
    System.out.println(readDeskeraPaInXmlToDeskeraPaInJson(deskeraPaInSampleXml));
  }

  @Test
  public void readJsonToDeskeraPaInElement_success()
      throws IOException, BankFormatConverterException {

    final String deskeraPaInSampleJson = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "JSON Request/DeskeraFastPayInit_Json.txt")));
    readJsonToDeskeraPaInElement(deskeraPaInSampleJson);
  }

  @Test
  public void convertFastPayJsonToPaIn001Xml_success()
      throws BankFormatConverterException, IOException, SAXException {

    final String deskeraPaInSampleJson = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "JSON Request/DeskeraFastPayInit_Json.txt")));
    final String pain001Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "XML Request/DeskeraFastISOXML.txt")));

    assertXMLEqual(pain001Sample, convertJsonToPaIn001Xml(deskeraPaInSampleJson));
  }

  @Test
  public void convertDftJsonToPaIn001Xml_success()
      throws BankFormatConverterException, IOException, SAXException {

    final String deskeraPaInSampleJson = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "JSON Request/DeskeraDFTinit_Json.txt")));
    final String pain001Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/OutgoingPayment/"
            + "XML Request/PaymentInitRequest_ISOXMLPlain_DFT.txt")));

    assertXMLEqual(pain001Sample, convertJsonToPaIn001Xml(deskeraPaInSampleJson));
  }
}