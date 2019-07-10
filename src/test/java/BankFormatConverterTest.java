package test.java;

import static main.java.BankFormatConverter.convertCamt052ToJson;
import static main.java.BankFormatConverter.convertCamt053ToDeskeraStatement;
import static main.java.BankFormatConverter.convertCamt053ToJson;
import static main.java.BankFormatConverter.convertDeskeraPaInXmlToDeskeraPaInJson;
import static main.java.BankFormatConverter.convertJsonToBalInqReqXml;
import static main.java.BankFormatConverter.convertJsonToPaIn001Xml;
import static main.java.BankFormatConverter.convertJsonToStatInitReqXml;
import static main.java.BankFormatConverter.convertPaIn002ToJson;
import static main.java.BankFormatConverter.createPayInitDocumentInstance;
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
import org.custommonkey.xmlunit.Diff;
import org.custommonkey.xmlunit.Difference;
import org.custommonkey.xmlunit.DifferenceConstants;
import org.custommonkey.xmlunit.DifferenceListener;
import org.custommonkey.xmlunit.ElementNameQualifier;
import org.custommonkey.xmlunit.XMLUnit;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

@RunWith(JUnit4.class)
public class BankFormatConverterTest extends TestCase {

  private static final String EMPTY_STRING = "";
  private static final String WHITE_SPACE = " ";
  private static final String SOME_XML = "<hi>123</hi>";
  private static final String SOME_JSON = "{key: value}";

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
  public void convertCamt053ToJson_sampleCamt053Sample_convertSuccess()
      throws BankFormatConverterException, IOException {

    final String camt053Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementRetrieval/XML Response/"
            + "StatementRetrieval_CAMT_053_001_02_File.txt")));
    String res = convertCamt053ToJson(camt053Sample);
    System.out.println(res);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertCamt053ToJson_emptyStr_throwsException()
      throws BankFormatConverterException {
    convertCamt053ToJson(EMPTY_STRING);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertCamt053ToJson_whiteSpace_throwsException()
      throws BankFormatConverterException {
    convertCamt053ToJson(WHITE_SPACE);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertCamt053ToJson_invalidXml_throwsException()
      throws BankFormatConverterException {
    convertCamt053ToJson(SOME_XML);
  }

  @Test
  public void convertCamt052ToJson_sampleCamt052Sample_convertSuccess()
      throws BankFormatConverterException, IOException {

    final String camt052Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Response/"
            + "BalanceInquiryResponse_Plain.txt")));
    String res = convertCamt052ToJson(camt052Sample);
    System.out.println(res);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertCamt052ToJson_emptyStr_throwsException()
      throws BankFormatConverterException {
    convertCamt052ToJson(EMPTY_STRING);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertCamt052ToJson_whiteSpace_throwsException()
      throws BankFormatConverterException {
    convertCamt052ToJson(WHITE_SPACE);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertCamt052ToJson_invalidXml_throwsException()
      throws BankFormatConverterException {
    convertCamt052ToJson(SOME_XML);
  }

  @Test
  public void convertPaIn002ToJson_samplePaIn002Sample_convertSuccess()
      throws BankFormatConverterException, IOException {

    final String pain002Sample = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/EnhancedPaymentStatusInquiry/"
            + "XML Response/paymentInq_Response.txt")));
    String res = convertPaIn002ToJson(pain002Sample);
    System.out.println(res);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertPaIn002ToJson_emptyStr_throwsException()
      throws BankFormatConverterException {
    convertPaIn002ToJson(EMPTY_STRING);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertPaIn002ToJson_whiteSpace_throwsException()
      throws BankFormatConverterException {
    convertPaIn002ToJson(WHITE_SPACE);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertPaIn002ToJson_invalidXml_throwsException()
      throws BankFormatConverterException {
    convertPaIn002ToJson(SOME_XML);
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
  public void convertDeskeraPaInXmlToDeskeraPaInJson_success()
      throws IOException, BankFormatConverterException {

    final String deskeraPaInSampleXml = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/PaymentInitiation/DeskeraFastPayment/"
            + "JSON Request/DeskeraFastPayInit_XML.txt")));
    System.out.println(convertDeskeraPaInXmlToDeskeraPaInJson(deskeraPaInSampleXml));
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

  @Test
  public void convertJsonToStatInitReqXml_success()
      throws BankFormatConverterException, IOException, SAXException {

    final String sampleJson = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementInitiation/CAMTorSWIFT/"
            + "XML Request/DeskeraStatInitRequest_CAMT_053_JSON.txt")));
    final String sampleXml = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/StatementInitiation/CAMTorSWIFT/XML Request/"
            + "StatementInitiationRequest_CAMT_053_001_02_Plain_Real.txt")));

    XMLUnit.setIgnoreWhitespace(true);

    // compare XMLs with xmlns (xml namespace) ignored
    Diff xmlDiff = new Diff(sampleXml, convertJsonToStatInitReqXml(sampleJson));
    xmlDiff.overrideElementQualifier(new ElementNameQualifier() {
      @Override
      protected boolean equalsNamespace(Node control, Node test) {
        return true;
      }
    });
    xmlDiff.overrideDifferenceListener(new DifferenceListener() {
      @Override
      public int differenceFound(Difference diff) {
        if (diff.getId() == DifferenceConstants.NAMESPACE_URI_ID) {
          return RETURN_IGNORE_DIFFERENCE_NODES_IDENTICAL;
        }
        return RETURN_ACCEPT_DIFFERENCE;
      }

      @Override
      public void skippedComparison(Node arg0, Node arg1) { }
    });
    assertXMLEqual(xmlDiff, true);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertJsonToStatInitReqXml_emptyStr_throwsException()
      throws BankFormatConverterException {
    convertJsonToStatInitReqXml(EMPTY_STRING);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertJsonToStatInitReqXml_whiteSpace_throwsException()
      throws BankFormatConverterException {
    convertJsonToStatInitReqXml(WHITE_SPACE);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertJsonToStatInitReqXml_invalidJson_throwsException()
      throws BankFormatConverterException {
    convertJsonToStatInitReqXml(SOME_JSON);
  }

  @Test
  public void convertJsonToBalInqReqXml_success()
      throws BankFormatConverterException, IOException, SAXException {

    final String sampleJson = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "DeskeraBalInqRequest_JSON.txt")));
    final String sampleXml = new String(Files.readAllBytes(Paths.get(
        "src/test/resources/sample/BalanceInquiry/XML Request/"
            + "BalanceInquiryRequest_Plain_Real.txt")));

    // compare XMLs with xmlns (xml namespace) ignored
    Diff xmlDiff = new Diff(sampleXml, convertJsonToBalInqReqXml(sampleJson));
    xmlDiff.overrideElementQualifier(new ElementNameQualifier() {
      @Override
      protected boolean equalsNamespace(Node control, Node test) {
        return true;
      }
    });
    xmlDiff.overrideDifferenceListener(new DifferenceListener() {
      @Override
      public int differenceFound(Difference diff) {
        if (diff.getId() == DifferenceConstants.NAMESPACE_URI_ID) {
          return RETURN_IGNORE_DIFFERENCE_NODES_IDENTICAL;
        }
        return RETURN_ACCEPT_DIFFERENCE;
      }

      @Override
      public void skippedComparison(Node arg0, Node arg1) { }
    });
    assertXMLEqual(xmlDiff, true);

  }

  @Test (expected = BankFormatConverterException.class)
  public void convertJsonToBalInqReqXml_emptyStr_throwsException()
      throws BankFormatConverterException {
    convertJsonToBalInqReqXml(EMPTY_STRING);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertJsonToBalInqReqXml_whiteSpace_throwsException()
      throws BankFormatConverterException {
    convertJsonToBalInqReqXml(WHITE_SPACE);
  }

  @Test (expected = BankFormatConverterException.class)
  public void convertJsonToBalInqReqXml_invalidJson_throwsException()
      throws BankFormatConverterException {
    convertJsonToBalInqReqXml(SOME_JSON);
  }

}
