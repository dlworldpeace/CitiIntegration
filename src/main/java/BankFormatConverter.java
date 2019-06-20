package main.java;

import static main.java.HandlerConstant.CAMT052_CLASS_PATH;
import static main.java.HandlerConstant.CAMT053_CLASS_PATH;
import static main.java.HandlerConstant.DESKERA_PAIN_CLASS_PATH;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import main.java.statement.DeskeraStatement;
import org.eclipse.persistence.jaxb.JAXBContextProperties;
import org.eclipse.persistence.jaxb.UnmarshallerProperties;

/**
 * This API supports all conversions between XML and Json via Format classes
 * generated using .xsd files.
 *
 * @author Sagar Mahamuni and Xiao Delong.
 * @version 1.0
 * @since 2019-06-12.
 */

public class BankFormatConverter<T> {

  private String classPath;

  public BankFormatConverter(String classPath) {
    this.classPath = classPath;
  }

  /**
   * Convert {@code XMLStr} in standard ISO format such as camt.053.001.02 to
   * a JAXBElement of rootElement.
   *
   * @param XMLStr XML String in standard ISO format.
   * @return a JAXBElement of a standard ISO format.
   * @throws BankFormatConverterException if an unexpected event happens during
   *                                      the conversion.
   */
  public JAXBElement<T> readXMLToElement (String XMLStr)
      throws BankFormatConverterException {
    try {
      JAXBContext jaxbContext = JAXBContext.newInstance(classPath);
      Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
      StringReader reader = new StringReader(XMLStr);
      return (JAXBElement<T>) unmarshaller.unmarshal(reader);
    } catch (JAXBException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new BankFormatConverterException(e.getMessage());
    }
  }

  /**
   * Convert {@code jsonStr} in standard ISO format such as camt.053.001.02 to
   * a JAXBElement of rootElement.
   *
   * @param jsonStr XML String in standard ISO format.
   * @return a JAXBElement of a standard ISO format.
   * @throws BankFormatConverterException if an unexpected event happens during
   *                                      the conversion.
   */
  public JAXBElement<T> readJsonToElement (String jsonStr)
      throws BankFormatConverterException {
    System.setProperty("javax.xml.bind.context.factory",
        "org.eclipse.persistence.jaxb.JAXBContextFactory");

    try {
      JAXBContext jaxbContext = JAXBContext.newInstance(classPath);
      Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
      unmarshaller.setProperty(JAXBContextProperties.MEDIA_TYPE, "application/json");
      unmarshaller.setProperty(JAXBContextProperties.JSON_INCLUDE_ROOT, true);
      StringReader reader = new StringReader(jsonStr);
      return (JAXBElement<T>) unmarshaller.unmarshal(reader);
    } catch (JAXBException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new BankFormatConverterException(e.getMessage());
    }
  }

  /**
   * Convert a JAXBElement of {@code rootElement} rooted at Document type to a
   * XML String of its corresponding standard ISO format such as camt.053.001.02.
   *
   * @param rootElement JAXBElement at rootElement of the seleceted structure.
   * @return corresponding XML String.
   * @throws BankFormatConverterException if an unexpected event happens during
   *                                      the conversion or adding some property
   *                                      to the string styles.
   */
  public String writeElementToXML (JAXBElement<T> rootElement)
      throws BankFormatConverterException {
    try {
    JAXBContext jaxbContext = JAXBContext.newInstance(classPath);
    Marshaller marshaller = jaxbContext.createMarshaller();
    OutputStream out = new ByteArrayOutputStream();
    DOMResult domResult = new DOMResult();
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
    marshaller.marshal(rootElement, domResult);
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.DOCTYPE_PUBLIC, "yes");
    transformer.setOutputProperty(OutputKeys.ENCODING, "utf-8");
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    transformer.setOutputProperty(
        "{http://xml.apache.org/xslt}indent-amount", "2");
    transformer.transform(new DOMSource(domResult.getNode()), new StreamResult(out));
    return out.toString();
    } catch (JAXBException | TransformerException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new BankFormatConverterException(e.getMessage());
    }
  }

  /**
   * Convert a JAXBElement of {@code rootElement} type to a JSON String of its
   * corresponding standard ISO format such as camt.053.001.02.
   *
   * @param rootElement JAXBElement at rootElement of the seleceted structure.
   * @return corresponding JSON String.
   * @throws BankFormatConverterException if an unexpected event happens during
   *                                      the conversion.
   */
  public String writeElementToJson (JAXBElement<T> rootElement)
      throws BankFormatConverterException {
    System.setProperty("javax.xml.bind.context.factory",
        "org.eclipse.persistence.jaxb.JAXBContextFactory");
    try {
      JAXBContext jaxbContext = JAXBContext.newInstance(classPath);
      Marshaller marshaller = jaxbContext.createMarshaller();
      marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
      marshaller.setProperty(JAXBContextProperties.MEDIA_TYPE, "application/json");
      marshaller.setProperty(JAXBContextProperties.JSON_INCLUDE_ROOT, false);
     StringWriter sw = new StringWriter();
     marshaller.marshal(rootElement, sw);
     return sw.toString();
    } catch (JAXBException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new BankFormatConverterException(e.getMessage());
    }
  }

  /**
   * Converter from camt.053.001.02 formatted String to its corresponding json
   * String.
   *
   * @param CAMT053Str XML string in ISO 20022 camt.053.001.02 format.
   * @return its corresponding json format string.
   * @throws BankFormatConverterException if an unexpected event occurs during
   *                                      the conversion process from XML String
   *                                      to JAXBElement and then to json String.
   */
  public static String readCAMT053ToJson(String CAMT053Str)
      throws BankFormatConverterException {
    BankFormatConverter<deskera.fintech.camt053.Document>
        converter = new BankFormatConverter<>(CAMT053_CLASS_PATH);
    JAXBElement<deskera.fintech.camt053.Document> documentElement =
        converter.readXMLToElement(CAMT053Str);
    return converter.writeElementToJson(documentElement);
  }

  /**
   * Converter from camt.052.001.02 formatted String to its corresponding json
   * String.
   *
   * @param CAMT052Str XML string in ISO 20022 camt.052.001.02 format.
   * @return its corresponding json format string.
   * @throws BankFormatConverterException if an unexpected event occurs during
   *                                      the conversion process from XML String
   *                                      to JAXBElement and then to json String.
   */
  public static String readCAMT052ToJson(String CAMT052Str)
      throws BankFormatConverterException {
    BankFormatConverter<deskera.fintech.camt052.Document>
        converter = new BankFormatConverter<>(CAMT052_CLASS_PATH);
    JAXBElement<deskera.fintech.camt052.Document> documentElement =
        converter.readXMLToElement(CAMT052Str);
    return converter.writeElementToJson(documentElement);
  }

  /**
   * Converter from deskera's payment initiation xml payload to deskera's payment
   * initiation json payload.
   *
   * @param DeskeraPaInXML XML string in deskera's custom format.
   * @return its corresponding json format string.
   * @throws BankFormatConverterException if an unexpected event occurs during
   *                                      the conversion process from XML String
   *                                      to JAXBElement and then to json String.
   */
  public static String readDeskeraPaInXMLToDeskeraPaInJson(String DeskeraPaInXML)
      throws BankFormatConverterException {
    BankFormatConverter<main.java.payinit.InitiatePayments>
        converter = new BankFormatConverter<>(DESKERA_PAIN_CLASS_PATH);
    JAXBElement<main.java.payinit.InitiatePayments> documentElement =
        converter.readXMLToElement(DeskeraPaInXML);
    return converter.writeElementToJson(documentElement);
  }

  /**
   * Converter from Json to Deskera's custom payment initiation formatted element
   *
   * @param jsonStr json string in Deskera's custom payment initiation format
   * @return its corresponding json format string.
   * @throws BankFormatConverterException if an unexpected event occurs during
   *                                      the conversion process from Json String
   *                                      to JAXBElement.
   */
  public static JAXBElement<main.java.payinit.InitiatePayments>
      readJsonToDeskeraPaInElement(String jsonStr) throws BankFormatConverterException {
    BankFormatConverter<main.java.payinit.InitiatePayments>
        converter = new BankFormatConverter<>(DESKERA_PAIN_CLASS_PATH);
    return converter.readJsonToElement(jsonStr);
  }

  /**
   * Convert type {@link deskera.fintech.camt053.Document} from End-of-the-day
   * statement file to simpler type {@link main.java.statement.DeskeraStatement}
   * for client to read.
   *
   * @param documentElement instance of {@link JAXBElement }{@code <}{@link deskera.fintech.camt053.Document}{@code >}
   * @return instance of {@link JAXBElement }{@code <}{@link main.java.statement.DeskeraStatement}{@code >}
   */
  public static JAXBElement<DeskeraStatement> convertCAMT053ToDeskeraStatement
      (JAXBElement<deskera.fintech.camt053.Document> documentElement) {

    DeskeraStatement deskeraStmt = new DeskeraStatement();
    deskera.fintech.camt053.Document document = documentElement.getValue();

    /* Start of Document */
      /* Start of BkToCstmrStmt */
    deskera.fintech.camt053.BankToCustomerStatementV02 bkToCstmrStmt =
        document.getBkToCstmrStmt();
        /* Start of GrpHdr */
    deskera.fintech.camt053.GroupHeader42 grpHdr = bkToCstmrStmt.getGrpHdr();
    deskeraStmt.setMsgId(grpHdr.getMsgId());
        /* End of GrpHdr */
        /* Start of Stmt */
    List<deskera.fintech.camt053.AccountStatement2> stmtList =
        bkToCstmrStmt.getStmt();
    deskera.fintech.camt053.AccountStatement2 stmt = stmtList.get(0);
    deskeraStmt.setStmtId(stmt.getId());
    deskeraStmt.setCreDtTm(stmt.getCreDtTm());
    deskeraStmt.setFrToDt(stmt.getFrToDt());
    deskera.fintech.camt053.CashAccount20 acct = stmt.getAcct();
    deskeraStmt.setAcctId(acct.getId().getOthr().getId());
    deskeraStmt.setAcctNm(acct.getNm());
    deskeraStmt.setAcctOwnrNm(acct.getOwnr().getNm());
    deskeraStmt.setAcctSvcr(acct.getSvcr());
    if (!stmt.getBal().isEmpty())
      deskeraStmt.setBal(stmt.getBal());
    if (!stmt.getIntrst().isEmpty())
      deskeraStmt.setIntrst(stmt.getIntrst());
    deskeraStmt.setTxsSummry(stmt.getTxsSummry());
    if (!stmt.getNtry().isEmpty())
      deskeraStmt.setNtry(stmt.getNtry());
        /* End of Stmt */
      /* End of BkToCstmrStmt */
    /* End of Document */

    return (new main.java.statement.ObjectFactory()).createStatement(deskeraStmt);
  }

//  /**
//   * Convert type {@link deskera.fintech.camt052.Document} from Intraday statement
//   * file to simpler type {@link main.java.statement.DeskeraStatement} for client
//   * to read.
//   *
//   * @param documentElement instance of {@link JAXBElement }{@code <}{@link deskera.fintech.camt052.Document}{@code >}
//   * @return instance of {@link JAXBElement }{@code <}{@link main.java.statement.DeskeraStatement}{@code >}
//   */
//  public static JAXBElement<DeskeraStatement> convertCAMT052ToDeskeraStatement
//  (JAXBElement<deskera.fintech.camt052.Document> documentElement) {
//
//    DeskeraStatement deskeraStmt = new DeskeraStatement();
//    deskera.fintech.camt052.Document document = documentElement.getValue();
//
//    /* Start of Document */
//    /* Start of BkToCstmrStmt */
//    deskera.fintech.camt052.BankToCustomerAccountReportV02 bkToCstmrAcctRpt =
//        document.getBkToCstmrAcctRpt();
//    /* Start of GrpHdr */
//    deskera.fintech.camt052.GroupHeader42 grpHdr = bkToCstmrAcctRpt.getGrpHdr();
//    deskeraStmt.setMsgId(grpHdr.getMsgId());
//    /* End of GrpHdr */
//    /* Start of Stmt */
//    List<deskera.fintech.camt052.AccountReport11> rptList =
//        bkToCstmrAcctRpt.getRpt();
//    deskera.fintech.camt052.AccountReport11 rpt = rptList.get(0);
//    deskeraStmt.setStmtId(rpt.getId());
//    deskeraStmt.setCreDtTm(rpt.getCreDtTm());
//    deskeraStmt.setFrToDt(rpt.getFrToDt());
//    deskera.fintech.camt052.CashAccount20 acct = rpt.getAcct();
//    deskeraStmt.setAcctId(acct.getId().getOthr().getId());
//    deskeraStmt.setAcctNm(acct.getNm());
//    deskeraStmt.setAcctOwnrNm(acct.getOwnr().getNm());
//    deskeraStmt.setAcctSvcr(acct.getSvcr());
//    if (!rpt.getBal().isEmpty())
//      deskeraStmt.setBal(rpt.getBal());
//    if (!rpt.getIntrst().isEmpty())
//      deskeraStmt.setIntrst(rpt.getIntrst());
//    deskeraStmt.setTxsSummry(rpt.getTxsSummry());
//    if (!rpt.getNtry().isEmpty())
//      deskeraStmt.setNtry(rpt.getNtry());
//    /* End of Stmt */
//    /* End of BkToCstmrStmt */
//    /* End of Document */
//
//    return (new main.java.statement.ObjectFactory()).createStatement(deskeraStmt);
//  }

}
