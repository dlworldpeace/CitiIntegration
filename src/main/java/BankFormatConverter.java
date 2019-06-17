package main.java;

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
   * a JAXBElement of rootElement fixed as Document type.
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
   * Convert a JAXBElement of {@code rootElement} rooted at Document type to a
   * XML String of its corresponding standard ISO format such as camt.053.001.02.
   *
   * @param rootElement JAXBElement rooted at Document Element.
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
   * Convert a JAXBElement of {@code rootElement} rooted at Document type to a
   * JSON String of its corresponding standard ISO format such as camt.053.001.02.
   *
   * @param rootElement JAXBElement rooted at Document Element.
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

}
