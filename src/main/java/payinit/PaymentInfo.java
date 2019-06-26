package main.java.payinit;

import deskera.fintech.pain001.PaymentMethod3Code;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.datatype.XMLGregorianCalendar;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PaymentInfo", propOrder = {
    "paymentRefId",
    "paymentMethod",
    "paymentTransType",
    "paymentDate",
    "debtor",
    "debtorAccount",
    "debtorBankInfo",
    "chargeBearer",
    "creditorTxnInfo"
})
public class PaymentInfo {

    @XmlElement(name = "PaymentRefId", required = true)
    protected String paymentRefId;
    @XmlElement(name = "PaymentMethod", required = true)
    @XmlSchemaType(name = "string")
    protected PaymentMethod3Code paymentMethod;
    @XmlElement(name = "PaymentTransType")
    protected PaymentTransType paymentTransType;
    @XmlElement(name = "PaymentDate", required = true)
    @XmlSchemaType(name = "date")
    protected XMLGregorianCalendar paymentDate;
    @XmlElement(name = "Debtor", required = true)
    protected Party debtor;
    @XmlElement(name = "DebtorAccount", required = true)
    protected String debtorAccount;
    @XmlElement(name = "DebtorBankInfo", required = true)
    protected BankInfo debtorBankInfo;
    @XmlElement(name = "ChargeBearer", required = true)
    protected String chargeBearer;
    @XmlElement(name = "CreditorTxnInfo", required = true)
    protected List<CreditorTxnInfo> creditorTxnInfo;

    /**
     * Gets the value of the paymentRefId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPaymentRefId() {
        return paymentRefId;
    }

    /**
     * Sets the value of the paymentRefId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPaymentRefId(String value) {
        this.paymentRefId = value;
    }

    /**
     * Gets the value of the paymentMethod property.
     * 
     * @return
     *     possible object is
     *     {@link PaymentMethod3Code }
     *     
     */
    public PaymentMethod3Code getPaymentMethod() {
        return paymentMethod;
    }

    /**
     * Sets the value of the paymentMethod property.
     * 
     * @param value
     *     allowed object is
     *     {@link PaymentMethod3Code }
     *     
     */
    public void setPaymentMethod(PaymentMethod3Code value) {
        this.paymentMethod = value;
    }

    /**
     * Gets the value of the paymentTransType property.
     * 
     * @return
     *     possible object is
     *     {@link PaymentTransType }
     *     
     */
    public PaymentTransType getPaymentTransType() {
        return paymentTransType;
    }

    /**
     * Sets the value of the paymentTransType property.
     * 
     * @param value
     *     allowed object is
     *     {@link PaymentTransType }
     *     
     */
    public void setPaymentTransType(PaymentTransType value) {
        this.paymentTransType = value;
    }

    /**
     * Gets the value of the paymentDate property.
     * 
     * @return
     *     possible object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public XMLGregorianCalendar getPaymentDate() {
        return paymentDate;
    }

    /**
     * Sets the value of the paymentDate property.
     * 
     * @param value
     *     allowed object is
     *     {@link XMLGregorianCalendar }
     *     
     */
    public void setPaymentDate(XMLGregorianCalendar value) {
        this.paymentDate = value;
    }

    /**
     * Gets the value of the debtor property.
     * 
     * @return
     *     possible object is
     *     {@link Party }
     *     
     */
    public Party getDebtor() {
        return debtor;
    }

    /**
     * Sets the value of the debtor property.
     * 
     * @param value
     *     allowed object is
     *     {@link Party }
     *     
     */
    public void setDebtor(Party value) {
        this.debtor = value;
    }

    /**
     * Gets the value of the debtorAccount property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDebtorAccount() {
        return debtorAccount;
    }

    /**
     * Sets the value of the debtorAccount property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDebtorAccount(String value) {
        this.debtorAccount = value;
    }

    /**
     * Gets the value of the debtorBankInfo property.
     * 
     * @return
     *     possible object is
     *     {@link BankInfo }
     *     
     */
    public BankInfo getDebtorBankInfo() {
        return debtorBankInfo;
    }

    /**
     * Sets the value of the debtorBankInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link BankInfo }
     *     
     */
    public void setDebtorBankInfo(BankInfo value) {
        this.debtorBankInfo = value;
    }

    /**
     * Gets the value of the chargeBearer property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getChargeBearer() {
        return chargeBearer;
    }

    /**
     * Sets the value of the chargeBearer property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setChargeBearer(String value) {
        this.chargeBearer = value;
    }

    /**
     * Gets the value of the creditorTxnInfo property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the creditorTxnInfo property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getCreditorTxnInfo().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link CreditorTxnInfo }
     * 
     * 
     */
    public List<CreditorTxnInfo> getCreditorTxnInfo() {
        if (creditorTxnInfo == null) {
            creditorTxnInfo = new ArrayList<CreditorTxnInfo>();
        }
        return this.creditorTxnInfo;
    }

}
