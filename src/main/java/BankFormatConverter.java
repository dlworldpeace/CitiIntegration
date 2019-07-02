package main.java;

import static main.java.Constant.CAMT052_CLASS_PATH;
import static main.java.Constant.CAMT053_CLASS_PATH;
import static main.java.Constant.DESKERA_PAIN_CLASS_PATH;
import static main.java.Constant.PAIN001_CLASS_PATH;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import main.java.statement.DeskeraStatement;
import main.java.payinit.*;
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
   * @return its corresponding {@link JAXBElement} {@code <}
   *         {@link main.java.payinit.InitiatePayments} {@code >} class instance
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
   * Convert type {@link main.java.payinit.InitiatePayments} from Deskera client
   * to ISOXML standard payment payload type {@link deskera.fintech.pain001.Document}
   * for initiating FAST or DFT payment
   *
   * @param deskeraPaIn instance of {@link JAXBElement }{@code <}{@link main.java.payinit.InitiatePayments}{@code >}
   * @return element instance of {@link JAXBElement }{@code <}{@link deskera.fintech.pain001.Document}{@code >}
   */
  public static JAXBElement<deskera.fintech.pain001.Document> convertDeskeraPaInToPAIN001
      (JAXBElement<main.java.payinit.InitiatePayments> deskeraPaIn) {

    InitiatePayments initiatePayments = deskeraPaIn.getValue();
    deskera.fintech.pain001.Document document = new deskera.fintech.pain001.Document();
    deskera.fintech.pain001.CustomerCreditTransferInitiationV03 cstmrCdtTrfInitn =
        new deskera.fintech.pain001.CustomerCreditTransferInitiationV03();
    document.setCstmrCdtTrfInitn(cstmrCdtTrfInitn);

    PaymentHeader paymentHeader = initiatePayments.getPaymentHeader();
    deskera.fintech.pain001.GroupHeader32 grpHdr =
        new deskera.fintech.pain001.GroupHeader32();
    cstmrCdtTrfInitn.setGrpHdr(grpHdr);
    grpHdr.setMsgId(paymentHeader.getPaymentRefId());
    grpHdr.setCreDtTm(paymentHeader.getDateTime());
    grpHdr.setNbOfTxs(paymentHeader.getNoOfTxs());
    deskera.fintech.pain001.PartyIdentification32 initgPty =
        new deskera.fintech.pain001.PartyIdentification32();
    grpHdr.setInitgPty(initgPty);
    initgPty.setNm(paymentHeader.getPartyName());

    PaymentInfo paymentInfo = initiatePayments.getPaymentInfo().get(0);
    deskera.fintech.pain001.PaymentInstructionInformation3 pmtInf =
        new deskera.fintech.pain001.PaymentInstructionInformation3();
    cstmrCdtTrfInitn.getPmtInf().add(pmtInf);
    pmtInf.setPmtInfId(paymentInfo.getPaymentRefId());
    pmtInf.setPmtMtd(paymentInfo.getPaymentMethod());
    deskera.fintech.pain001.PaymentTypeInformation19 pmtTpInf =
        new deskera.fintech.pain001.PaymentTypeInformation19();
    pmtInf.setPmtTpInf(pmtTpInf);
    deskera.fintech.pain001.ServiceLevel8Choice svcLvl =
        new deskera.fintech.pain001.ServiceLevel8Choice();
    pmtTpInf.setSvcLvl(svcLvl);
    PaymentTransTypeCode paymentTransType = paymentInfo.getPaymentTransType();
    if (paymentTransType == PaymentTransTypeCode.DFT) {
      svcLvl.setCd("URGP");
    } else {
      svcLvl.setCd("URNS");
      deskera.fintech.pain001.LocalInstrument2Choice lclInstrm =
          new deskera.fintech.pain001.LocalInstrument2Choice();
      pmtTpInf.setLclInstrm(lclInstrm);
      lclInstrm.setPrtry("SGIP");
    }
    pmtInf.setReqdExctnDt(paymentInfo.getPaymentDate());

    deskera.fintech.pain001.PartyIdentification32 dbtr =
        new deskera.fintech.pain001.PartyIdentification32();
    pmtInf.setDbtr(dbtr);
    Party debtor = paymentInfo.getDebtor();
    dbtr.setNm(debtor.getName());
    deskera.fintech.pain001.PostalAddress6 pstlAdr =
        new deskera.fintech.pain001.PostalAddress6();
    dbtr.setPstlAdr(pstlAdr);
    pstlAdr.setCtry(debtor.getAddress().getCountryCode());
    if (!debtor.getAddress().getAdrLine().isEmpty())
      pstlAdr.getAdrLine().addAll(debtor.getAddress().getAdrLine());

    deskera.fintech.pain001.CashAccount16 dbtrAcct =
        new deskera.fintech.pain001.CashAccount16();
    pmtInf.setDbtrAcct(dbtrAcct);
    deskera.fintech.pain001.AccountIdentification4Choice dbtrAcctId =
        new deskera.fintech.pain001.AccountIdentification4Choice();
    dbtrAcct.setId(dbtrAcctId);
    deskera.fintech.pain001.GenericAccountIdentification1 othr =
        new deskera.fintech.pain001.GenericAccountIdentification1();
    dbtrAcctId.setOthr(othr);
    othr.setId(paymentInfo.getDebtorAccount());
    dbtrAcct.setCcy(paymentInfo.getDebtorAcctCurrency());

    BankInfo debtorBankInfo = paymentInfo.getDebtorBankInfo();
    deskera.fintech.pain001.BranchAndFinancialInstitutionIdentification4 dbtrAgt =
        new deskera.fintech.pain001.BranchAndFinancialInstitutionIdentification4();
    pmtInf.setDbtrAgt(dbtrAgt);
    deskera.fintech.pain001.FinancialInstitutionIdentification7 finInstnId =
        new deskera.fintech.pain001.FinancialInstitutionIdentification7();
    dbtrAgt.setFinInstnId(finInstnId);
    finInstnId.setBIC(debtorBankInfo.getBIC());
    deskera.fintech.pain001.PostalAddress6 pstlAdr2 =
        new deskera.fintech.pain001.PostalAddress6();
    finInstnId.setPstlAdr(pstlAdr2);
    pstlAdr2.setCtry(debtorBankInfo.getAddress().getCountryCode());
    pmtInf.setChrgBr(
        deskera.fintech.pain001.ChargeBearerType1Code.valueOf(paymentInfo.getChargeBearer()));

    CreditorTxnInfo creditorTxnInfo = paymentInfo.getCreditorTxnInfo().get(0);
    deskera.fintech.pain001.CreditTransferTransactionInformation10 cdtTrfTxInf =
        new deskera.fintech.pain001.CreditTransferTransactionInformation10();
    pmtInf.getCdtTrfTxInf().add(cdtTrfTxInf);
    deskera.fintech.pain001.PaymentIdentification1 pmtId =
        new deskera.fintech.pain001.PaymentIdentification1();
    cdtTrfTxInf.setPmtId(pmtId);
    pmtId.setEndToEndId(creditorTxnInfo.getEndToEndId());
    deskera.fintech.pain001.AmountType3Choice amt =
        new deskera.fintech.pain001.AmountType3Choice();
    cdtTrfTxInf.setAmt(amt);
    deskera.fintech.pain001.ActiveOrHistoricCurrencyAndAmount instdAmt =
        new deskera.fintech.pain001.ActiveOrHistoricCurrencyAndAmount();
    amt.setInstdAmt(instdAmt);
    instdAmt.setValue(creditorTxnInfo.getAmount());
    instdAmt.setCcy(creditorTxnInfo.getAmountCurrency());
    deskera.fintech.pain001.BranchAndFinancialInstitutionIdentification4 cdtrAgt =
        new deskera.fintech.pain001.BranchAndFinancialInstitutionIdentification4();
    cdtTrfTxInf.setCdtrAgt(cdtrAgt);
    BankInfo creditorBankInfo = creditorTxnInfo.getCreditorBankInfo();
    deskera.fintech.pain001.FinancialInstitutionIdentification7 finInstnId2 =
        new deskera.fintech.pain001.FinancialInstitutionIdentification7();
    cdtrAgt.setFinInstnId(finInstnId2);
    finInstnId2.setBIC(creditorBankInfo.getBIC());
    finInstnId2.setNm(creditorBankInfo.getName());
    if (creditorBankInfo.getAddress() != null) {
      deskera.fintech.pain001.PostalAddress6 pstlAdr3 =
          new deskera.fintech.pain001.PostalAddress6();
      finInstnId2.setPstlAdr(pstlAdr3);
      pstlAdr3.setCtry(creditorBankInfo.getAddress().getCountryCode());
    }

    Party creditor = creditorTxnInfo.getCreditor();
    deskera.fintech.pain001.PartyIdentification32 cdtr =
        new deskera.fintech.pain001.PartyIdentification32();
    cdtTrfTxInf.setCdtr(cdtr);
    cdtr.setNm(creditor.getName());
    deskera.fintech.pain001.PostalAddress6 pstlAdr4 =
        new deskera.fintech.pain001.PostalAddress6();
    cdtr.setPstlAdr(pstlAdr4);
    pstlAdr4.setCtry(creditor.getAddress().getCountryCode());
    if (!creditor.getAddress().getAdrLine().isEmpty())
      pstlAdr4.getAdrLine().addAll(creditor.getAddress().getAdrLine());

    deskera.fintech.pain001.CashAccount16 cdtrAcct =
        new deskera.fintech.pain001.CashAccount16();
    cdtTrfTxInf.setCdtrAcct(cdtrAcct);
    deskera.fintech.pain001.AccountIdentification4Choice cdtrAcctId =
        new deskera.fintech.pain001.AccountIdentification4Choice();
    cdtrAcct.setId(cdtrAcctId);
    deskera.fintech.pain001.GenericAccountIdentification1 cdtrOthr =
        new deskera.fintech.pain001.GenericAccountIdentification1();
    cdtrAcctId.setOthr(cdtrOthr);
    cdtrOthr.setId(creditorTxnInfo.getCreditorAccount());

    if (creditorTxnInfo.getPurpose() != null) {
      deskera.fintech.pain001.Purpose2Choice purp =
          new deskera.fintech.pain001.Purpose2Choice();
      cdtTrfTxInf.setPurp(purp);
      purp.setPrtry(creditorTxnInfo.getPurpose());
    }

    deskera.fintech.pain001.RemittanceInformation5 rmtInf =
        new deskera.fintech.pain001.RemittanceInformation5();
    cdtTrfTxInf.setRmtInf(rmtInf);
    rmtInf.getUstrd().add(creditorTxnInfo.getRemittanceInfo());

    return (new deskera.fintech.pain001.ObjectFactory()).createDocument(document);
  }

  /**
   * Converter from Deskera's custom payment initiation formatted Json String to
   * its corresponding Xml String in pain.001.001.03 standards.
   *
   * @param jsonStr Json string in Deskera's custom payment initiation format.
   * @return its corresponding xml string in pain.001.001.03 standards.
   * @throws BankFormatConverterException if an unexpected event occurs during
   *                                      the conversion process.
   */
  public static String convertJsonToPAIN001XML (String jsonStr)
      throws BankFormatConverterException {
    JAXBElement<main.java.payinit.InitiatePayments> initiatePaymentsElement =
        readJsonToDeskeraPaInElement(jsonStr);
    JAXBElement<deskera.fintech.pain001.Document> documentElement =
        convertDeskeraPaInToPAIN001(initiatePaymentsElement);
    BankFormatConverter<deskera.fintech.pain001.Document>
        converter = new BankFormatConverter<>(PAIN001_CLASS_PATH);
    return converter.writeElementToXML(documentElement);
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

  /**
   * Create a document class instance based on pain.001.001.03 format.
   *
   * @return pain format document object.
   * @throws DatatypeConfigurationException if an unexpected event happens when
   *                                        creating datatype instances.
   */
  public static deskera.fintech.pain001.Document createPayInitDocumentInstance()
      throws DatatypeConfigurationException {
    DatatypeFactory dataType = DatatypeFactory.newInstance();

    /* Start of Document */
    deskera.fintech.pain001.Document document =
        new deskera.fintech.pain001.Document();
    /* Start of cstmrCdtTrfInitn */
    deskera.fintech.pain001.CustomerCreditTransferInitiationV03 cstmrCdtTrfInitn =
        new deskera.fintech.pain001.CustomerCreditTransferInitiationV03();
    /* Start of GrpHdr */
    deskera.fintech.pain001.GroupHeader32 grpHdr =
        new deskera.fintech.pain001.GroupHeader32();
    grpHdr.setMsgId("GBP161111000001");
    XMLGregorianCalendar creDtTm =
        dataType.newXMLGregorianCalendar(2016,11,11,3, 51, 15, 0, 0);
    creDtTm.setMillisecond(DatatypeConstants.FIELD_UNDEFINED);
    creDtTm.setTimezone(DatatypeConstants.FIELD_UNDEFINED);
    grpHdr.setCreDtTm(creDtTm);
    grpHdr.setNbOfTxs("1");
    grpHdr.setCtrlSum(new BigDecimal("1.00"));
    deskera.fintech.pain001.PartyIdentification32 initgPty =
        new deskera.fintech.pain001.PartyIdentification32();
    initgPty.setNm("ABC");
    grpHdr.setInitgPty(initgPty);
    cstmrCdtTrfInitn.setGrpHdr(grpHdr);
    /* End of GrpHdr */
    /* Start of PmtInf */
    List<deskera.fintech.pain001.PaymentInstructionInformation3> pmtInfList =
        cstmrCdtTrfInitn.getPmtInf();
    deskera.fintech.pain001.PaymentInstructionInformation3 pmtInf =
        new deskera.fintech.pain001.PaymentInstructionInformation3();
    pmtInfList.add(pmtInf);
    pmtInf.setPmtInfId("98765432 Fund Transfer Domestic");
    pmtInf.setPmtMtd(deskera.fintech.pain001.PaymentMethod3Code.TRF);
    pmtInf.setNbOfTxs("1");
    pmtInf.setCtrlSum(new BigDecimal("1.00"));
    deskera.fintech.pain001.PaymentTypeInformation19 pmtTpInf =
        new deskera.fintech.pain001.PaymentTypeInformation19();
    deskera.fintech.pain001.ServiceLevel8Choice svcLvl =
        new deskera.fintech.pain001.ServiceLevel8Choice();
    svcLvl.setCd("URGP");
    pmtTpInf.setSvcLvl(svcLvl);
    pmtInf.setPmtTpInf(pmtTpInf);
    XMLGregorianCalendar reqdExctnDt =
        dataType.newXMLGregorianCalendarDate(2016,11,16, 0);
    reqdExctnDt.setTimezone(DatatypeConstants.FIELD_UNDEFINED);
    pmtInf.setReqdExctnDt(reqdExctnDt);
    /* Start of Dbtr */
    deskera.fintech.pain001.PartyIdentification32 dbtr =
        new deskera.fintech.pain001.PartyIdentification32();
    dbtr.setNm("ABCD DEMO");
    deskera.fintech.pain001.PostalAddress6 pstlAdr1 =
        new deskera.fintech.pain001.PostalAddress6();
    pstlAdr1.setCtry("GB");
    dbtr.setPstlAdr(pstlAdr1);
    deskera.fintech.pain001.Party6Choice id1 =
        new deskera.fintech.pain001.Party6Choice();
    deskera.fintech.pain001.OrganisationIdentification4 orgId =
        new deskera.fintech.pain001.OrganisationIdentification4();
    orgId.setBICOrBEI("CITIGB2L");
    id1.setOrgId(orgId);
    dbtr.setId(id1);
    pmtInf.setDbtr(dbtr);
    /* End of Dbtr */
    /* Start of DbtrAcct */
    deskera.fintech.pain001.CashAccount16 dbtrAcct =
        new deskera.fintech.pain001.CashAccount16();
    deskera.fintech.pain001.AccountIdentification4Choice id2 =
        new deskera.fintech.pain001.AccountIdentification4Choice();
    deskera.fintech.pain001.GenericAccountIdentification1 othr1 =
        new deskera.fintech.pain001.GenericAccountIdentification1();
    othr1.setId("12345678");
    id2.setOthr(othr1);
    dbtrAcct.setId(id2);
    dbtrAcct.setCcy("USD");
    pmtInf.setDbtrAcct(dbtrAcct);
    /* End of DbtrAcct */
    /* Start of DbtrAgt */
    deskera.fintech.pain001.BranchAndFinancialInstitutionIdentification4 dbtrAgt1 =
        new deskera.fintech.pain001.BranchAndFinancialInstitutionIdentification4();
    deskera.fintech.pain001.FinancialInstitutionIdentification7 finInstnId =
        new deskera.fintech.pain001.FinancialInstitutionIdentification7();
    finInstnId.setBIC("CITIGB2L");
    deskera.fintech.pain001.PostalAddress6 pstlAdr2 =
        new deskera.fintech.pain001.PostalAddress6();
    pstlAdr2.setCtry("GB");
    finInstnId.setPstlAdr(pstlAdr2);
    dbtrAgt1.setFinInstnId(finInstnId);
    pmtInf.setDbtrAgt(dbtrAgt1);
    /* End of DbtrAgt */
    pmtInf.setChrgBr(deskera.fintech.pain001.ChargeBearerType1Code.DEBT);
    /* Start of cdtTrfTxInf */
    List<deskera.fintech.pain001.CreditTransferTransactionInformation10> cdtTrfTxInfList =
        pmtInf.getCdtTrfTxInf();
    deskera.fintech.pain001.CreditTransferTransactionInformation10 cdtTrfTxInf =
        new deskera.fintech.pain001.CreditTransferTransactionInformation10();
    /* Start of PmtId */
    deskera.fintech.pain001.PaymentIdentification1 pmtId =
        new deskera.fintech.pain001.PaymentIdentification1();
    pmtId.setEndToEndId("ABC1234");
    cdtTrfTxInf.setPmtId(pmtId);
    /* End of PmtId */
    /* Start of Amt */
    deskera.fintech.pain001.AmountType3Choice amt =
        new deskera.fintech.pain001.AmountType3Choice();
    deskera.fintech.pain001.ActiveOrHistoricCurrencyAndAmount instdAmt =
        new deskera.fintech.pain001.ActiveOrHistoricCurrencyAndAmount();
    instdAmt.setCcy("USD");
    instdAmt.setValue(new BigDecimal("1.00"));
    amt.setInstdAmt(instdAmt);
    cdtTrfTxInf.setAmt(amt);
    /* Start of UltmtDbtr */
    deskera.fintech.pain001.PartyIdentification32 ultmtDbtr =
        new deskera.fintech.pain001.PartyIdentification32();
    deskera.fintech.pain001.Party6Choice id3 =
        new deskera.fintech.pain001.Party6Choice();
    deskera.fintech.pain001.PersonIdentification5 prvtId =
        new deskera.fintech.pain001.PersonIdentification5();
    List<deskera.fintech.pain001.GenericPersonIdentification1> othrList =
        prvtId.getOthr();
    deskera.fintech.pain001.GenericPersonIdentification1 othr = new
        deskera.fintech.pain001.GenericPersonIdentification1();
    othr.setId("ABCDEF UK BR600 012345");
    deskera.fintech.pain001.PersonIdentificationSchemeName1Choice schmeNm =
        new deskera.fintech.pain001.PersonIdentificationSchemeName1Choice();
    schmeNm.setPrtry("INST");
    othr.setSchmeNm(schmeNm);
    othrList.add(othr);
    id3.setPrvtId(prvtId);
    ultmtDbtr.setId(id3);
    cdtTrfTxInf.setUltmtDbtr(ultmtDbtr);
    /* End of UltmtDbtr */
    /* Start of CdtrAgt */
    deskera.fintech.pain001.BranchAndFinancialInstitutionIdentification4 cdtrAgt2 =
        new deskera.fintech.pain001.BranchAndFinancialInstitutionIdentification4();
    deskera.fintech.pain001.FinancialInstitutionIdentification7 finInstnId2 =
        new deskera.fintech.pain001.FinancialInstitutionIdentification7();
    finInstnId2.setBIC("CITIGB2L");
    deskera.fintech.pain001.ClearingSystemMemberIdentification2 clrSysMmbId =
        new deskera.fintech.pain001.ClearingSystemMemberIdentification2();
    clrSysMmbId.setMmbId("185008");
    finInstnId2.setClrSysMmbId(clrSysMmbId);
    finInstnId2.setNm("CITIBANK(ISO)");
    deskera.fintech.pain001.PostalAddress6 pstlAdr3 =
        new deskera.fintech.pain001.PostalAddress6();
    pstlAdr3.setCtry("GB");
    finInstnId2.setPstlAdr(pstlAdr3);
    cdtrAgt2.setFinInstnId(finInstnId2);
    cdtTrfTxInf.setCdtrAgt(cdtrAgt2);
    /* End of CdtrAgt */
    /* Start of Cdtr */
    deskera.fintech.pain001.PartyIdentification32 cdtr =
        new deskera.fintech.pain001.PartyIdentification32();
    cdtr.setNm("8010643122X XXXXXXXXXXXXX XXX");
    deskera.fintech.pain001.PostalAddress6 pstlAdr4 =
        new deskera.fintech.pain001.PostalAddress6();
    pstlAdr4.setCtry("GB");
    cdtr.setPstlAdr(pstlAdr4);
    deskera.fintech.pain001.ContactDetails2 ctctDtls =
        new deskera.fintech.pain001.ContactDetails2();
    ctctDtls.setNm("ABC LIMITED");
    cdtr.setCtctDtls(ctctDtls);
    cdtTrfTxInf.setCdtr(cdtr);
    /* End of Cdtr */
    /* Start of CdtrAcct */
    deskera.fintech.pain001.CashAccount16 cdtrAcct =
        new deskera.fintech.pain001.CashAccount16();
    deskera.fintech.pain001.AccountIdentification4Choice id4 =
        new deskera.fintech.pain001.AccountIdentification4Choice();
    id4.setIBAN("GB27CITI18500812345678");
    cdtrAcct.setId(id4);
    cdtTrfTxInf.setCdtrAcct(cdtrAcct);
    /* End of CdtrAcct */
    /* Start of RmtInf */
    deskera.fintech.pain001.RemittanceInformation5 rmtInf =
        new deskera.fintech.pain001.RemittanceInformation5();
    List<String> ustrdList = rmtInf.getUstrd();
    ustrdList.add("TR002638");
    cdtTrfTxInf.setRmtInf(rmtInf);
    /* End of RmtInf */
    cdtTrfTxInfList.add(cdtTrfTxInf);
    /* End of cdtTrfTxInf */
    /* End of PmtInf */
    /* End of cstmrCdtTrfInitn */
    document.setCstmrCdtTrfInitn(cstmrCdtTrfInitn);
    /* End of Document */

    return document;
  }

}
