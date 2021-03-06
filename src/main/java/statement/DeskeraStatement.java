//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.3.0-b170531.0717 
//         See <a href="https://jaxb.java.net/">https://jaxb.java.net/</a> 
//         Any modifications to this file will be lost upon recompilation of the source schema. 
//         Generated on: 2019.06.13 at 04:19:56 PM CST 
//


package main.java.statement;

import deskera.fintech.camt053.BranchAndFinancialInstitutionIdentification4;
import deskera.fintech.camt053.DateTimePeriodDetails;
import deskera.fintech.camt053.TotalTransactions2;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;


/**
 * <p>Java class for AccountStatement2 complex type.
 * 
 * <p>The following schema fragment specifies the expected         content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AccountStatement2"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="Id" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}Max35Text"/&gt;
 *         &lt;element name="ElctrncSeqNb" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}Number" minOccurs="0"/&gt;
 *         &lt;element name="LglSeqNb" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}Number" minOccurs="0"/&gt;
 *         &lt;element name="CreDtTm" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}ISODateTime"/&gt;
 *         &lt;element name="FrToDt" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}DateTimePeriodDetails" minOccurs="0"/&gt;
 *         &lt;element name="CpyDplctInd" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}CopyDuplicate1Code" minOccurs="0"/&gt;
 *         &lt;element name="RptgSrc" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}ReportingSource1Choice" minOccurs="0"/&gt;
 *         &lt;element name="Acct" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}CashAccount20"/&gt;
 *         &lt;element name="RltdAcct" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}CashAccount16" minOccurs="0"/&gt;
 *         &lt;element name="Intrst" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}AccountInterest2" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="Bal" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}CashBalance3" maxOccurs="unbounded"/&gt;
 *         &lt;element name="TxsSummry" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}TotalTransactions2" minOccurs="0"/&gt;
 *         &lt;element name="Ntry" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}ReportEntry2" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="AddtlStmtInf" type="{urn:iso:std:iso:20022:tech:xsd:camt.053.001.02}Max500Text" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DeskeraStatement", propOrder = {
    "msgId",
    "stmtId",
    "creDtTm",
    "frToDt",
    "acctId",
    "acctNm",
    "acctOwnrNm",
    "acctSvcr",
//    "rltdAcct",
    "intrst",
    "bal",
    "txsSummry",
    "ntry"
})
public class DeskeraStatement {

    @XmlElement(name = "MsgId", required = true)
    protected String msgId;
    @XmlElement(name = "StmtId", required = true)
    protected String stmtId;
    @XmlElement(name = "CreDtTm", required = true)
    @XmlSchemaType(name = "dateTime")
    protected XMLGregorianCalendar creDtTm;
    @XmlElement(name = "FrToDt")
    protected DateTimePeriodDetails frToDt;
//    @XmlElement(name = "RltdAcct") // TODO: check if this is needed
//    protected deskera.fintech.camt053.CashAccount16 rltdAcct;
    @XmlElement(name = "AcctId", required = true)
    protected String acctId;
    @XmlElement(name = "AcctOwnrNm")
    protected String acctOwnrNm;
    @XmlElement(name = "AcctNm")
    protected String acctNm;
    @XmlElement(name = "AcctSvcr")
    protected BranchAndFinancialInstitutionIdentification4 acctSvcr;
    @XmlElement(name = "Intrst")
    protected List<deskera.fintech.camt053.AccountInterest2> intrst;
    @XmlElement(name = "Bal", required = true)
    protected List<deskera.fintech.camt053.CashBalance3> bal;
    @XmlElement(name = "TxsSummry")
    protected TotalTransactions2 txsSummry;
    @XmlElement(name = "Ntry")
    protected List<deskera.fintech.camt053.ReportEntry2> ntry;

    /**
     * Gets the value of the msgId property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getMsgId() {
        return this.msgId;
    }

    /**
     * Sets the value of the msgId property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setMsgId(String value) {
        this.msgId = value;
    }

    /**
     * Gets the value of the stmtId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getStmtId() {
        return stmtId;
    }

    /**
     * Sets the value of the stmtId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setStmtId(String value) {
        this.stmtId = value;
    }

    /**
     * Gets the value of the creDtTm property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getCreDtTm() {
        return creDtTm;
    }

    /**
     * Sets the value of the creDtTm property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setCreDtTm(XMLGregorianCalendar value) {
        this.creDtTm = value;
    }

    /**
     * Gets the value of the frToDt property.
     * 
     * @return
     *     possible object is
     *     {@link DateTimePeriodDetails }
     *     
     */
    public DateTimePeriodDetails getFrToDt() {
        return frToDt;
    }

    /**
     * Sets the value of the frToDt property.
     * 
     * @param value
     *     allowed object is
     *     {@link DateTimePeriodDetails }
     *     
     */
    public void setFrToDt(DateTimePeriodDetails value) {
        this.frToDt = value;
    }

    /**
     * Gets the value of the acctId property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getAcctId() {
        return this.acctId;
    }

    /**
     * Sets the value of the acctId property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setAcctId(String value) {
        this.acctId = value;
    }

    /**
     * Gets the value of the acctOwnrNm property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getAcctOwnrNm() {
        return this.acctOwnrNm;
    }

    /**
     * Sets the value of the acctOwnrNm property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setAcctOwnrNm(String value) {
        this.acctOwnrNm = value;
    }

    /**
     * Gets the value of the acctNm property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getAcctNm() {
        return this.acctNm;
    }

    /**
     * Sets the value of the acctNm property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setAcctNm(String value) {
        this.acctNm = value;
    }

    /**
     * Gets the value of the acctSvcr property.
     *
     * @return
     *     possible object is
     *     {@link BranchAndFinancialInstitutionIdentification4 }
     *
     */
    public BranchAndFinancialInstitutionIdentification4 getAcctSvcr() {
        return this.acctSvcr;
    }

    /**
     * Sets the value of the acctSvcr property.
     *
     * @param value
     *     allowed object is
     *     {@link BranchAndFinancialInstitutionIdentification4 }
     *
     */
    public void setAcctSvcr(BranchAndFinancialInstitutionIdentification4 value) {
        this.acctSvcr = value;
    }

//    /**
//     * Gets the value of the rltdAcct property.
//     *
//     * @return
//     *     possible object is
//     *     {@link deskera.fintech.camt053.CashAccount16 }
//     *
//     */
//    public deskera.fintech.camt053.CashAccount16 getRltdAcct() {
//        return rltdAcct;
//    }
//
//    /**
//     * Sets the value of the rltdAcct property.
//     *
//     * @param value
//     *     allowed object is
//     *     {@link deskera.fintech.camt053.CashAccount16 }
//     *
//     */
//    public void setRltdAcct(CashAccount16 value) {
//        this.rltdAcct = value;
//    }

    /**
     * Gets the value of the intrst property.
     *
     * @return
     *     a reference to the live list of intrst
     *
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link deskera.fintech.camt053.AccountInterest2 }
     *
     */
    public List<deskera.fintech.camt053.AccountInterest2> getIntrst() {
        return this.intrst;
    }

    /**
     * Sets the value of the intrst property.
     *
     * @param intrstList
     *     allowed object is
     *     {@link List<deskera.fintech.camt053.AccountInterest2> }
     *
     */
    public void setIntrst(List<deskera.fintech.camt053.AccountInterest2> intrstList) {
        this.intrst = intrstList;
    }

    /**
     * Gets the value of the bal property.
     *
     * @return
     *     a reference to the live list of bal
     *
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link deskera.fintech.camt053.CashBalance3 }
     *
     */
    public List<deskera.fintech.camt053.CashBalance3> getBal() {
        return this.bal;
    }

    /**
     * Sets the value of the bal property.
     *
     * @param balList
     *     allowed object is
     *     {@link List<deskera.fintech.camt053.CashBalance3> }
     *
     */
    public void setBal(List<deskera.fintech.camt053.CashBalance3> balList) {
        this.bal = balList;
    }

    /**
     * Gets the value of the txsSummry property.
     * 
     * @return
     *     possible object is
     *     {@link TotalTransactions2 }
     *     
     */
    public TotalTransactions2 getTxsSummry() {
        return txsSummry;
    }

    /**
     * Sets the value of the txsSummry property.
     * 
     * @param value
     *     allowed object is
     *     {@link TotalTransactions2 }
     *     
     */
    public void setTxsSummry(TotalTransactions2 value) {
        this.txsSummry = value;
    }

    /**
     * Gets the value of the ntry property.
     *
     * @return
     *     a reference to the live list of ntry
     *
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link deskera.fintech.camt053.ReportEntry2 }
     *
     */
    public List<deskera.fintech.camt053.ReportEntry2> getNtry() {
        return this.ntry;
    }

    /**
     * Sets the value of the ntry property.
     *
     * @param ntryList
     *     allowed object is
     *     {@link List<deskera.fintech.camt053.ReportEntry2> }
     *
     */
    public void setNtry(List<deskera.fintech.camt053.ReportEntry2> ntryList) {
        this.ntry = ntryList;
    }

}
