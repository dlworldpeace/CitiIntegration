package main.java.payinit;

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
    "payRefId",
    "payMethod",
    "paymentTrasType",
    "paymentDate",
    "debtorName",
    "debtorAcc",
    "debtorBankDetails",
    "creditorTxnInfo"
})
public class PaymentInfo {

    @XmlElement(name = "PayRefId", required = true)
    protected String payRefId;
    @XmlElement(name = "PayMethod", required = true)
    @XmlSchemaType(name = "string")
    protected PaymentMethod3Code payMethod;
    @XmlElement(name = "PaymentTrasType")
    protected PaymentTransType paymentTrasType; // TODO
    @XmlElement(name = "PaymentDate", required = true)
    @XmlSchemaType(name = "date")
    protected XMLGregorianCalendar paymentDate;
    @XmlElement(name = "DebtorName", required = true)
    protected String debtorName;
    @XmlElement(name = "DebtorAcc", required = true)
    protected String debtorAcc;
    @XmlElement(name = "DebtorBankDetails", required = true)
    protected BankDetails debtorBankDetails;
    @XmlElement(name = "CreditorTxnInfo", required = true)
    protected List<CreditorTxnInfo> creditorTxnInfo;

    /**
     * Gets the value of the payRefId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPayRefId() {
        return payRefId;
    }

    /**
     * Sets the value of the payRefId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPayRefId(String value) {
        this.payRefId = value;
    }

    /**
     * Gets the value of the payMethod property.
     * 
     * @return
     *     possible object is
     *     {@link PaymentMethod3Code }
     *     
     */
    public PaymentMethod3Code getPayMethod() {
        return payMethod;
    }

    /**
     * Sets the value of the payMethod property.
     * 
     * @param value
     *     allowed object is
     *     {@link PaymentMethod3Code }
     *     
     */
    public void setPayMethod(PaymentMethod3Code value) {
        this.payMethod = value;
    }

    /**
     * Gets the value of the paymentTrasType property.
     * 
     * @return
     *     possible object is
     *     {@link PaymentTransType }
     *     
     */
    public PaymentTransType getPaymentTrasType() {
        return paymentTrasType;
    }

    /**
     * Sets the value of the paymentTrasType property.
     * 
     * @param value
     *     allowed object is
     *     {@link PaymentTransType }
     *     
     */
    public void setPaymentTrasType(PaymentTransType value) {
        this.paymentTrasType = value;
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
     * Gets the value of the debtorName property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDebtorName() {
        return debtorName;
    }

    /**
     * Sets the value of the debtorName property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDebtorName(String value) {
        this.debtorName = value;
    }

    /**
     * Gets the value of the debtorAcc property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getDebtorAcc() {
        return debtorAcc;
    }

    /**
     * Sets the value of the debtorAcc property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setDebtorAcc(String value) {
        this.debtorAcc = value;
    }

    /**
     * Gets the value of the debtorBankDetails property.
     * 
     * @return
     *     possible object is
     *     {@link BankDetails }
     *     
     */
    public BankDetails getDebtorBankDetails() {
        return debtorBankDetails;
    }

    /**
     * Sets the value of the debtorBankDetails property.
     * 
     * @param value
     *     allowed object is
     *     {@link BankDetails }
     *     
     */
    public void setDebtorBankDetails(BankDetails value) {
        this.debtorBankDetails = value;
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
