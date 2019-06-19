package main.java.payinit;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CreditorTxnInfo", propOrder = {
    "trxId",
    "amountInfo",
    "creditBankInfo",
    "creditor",
    "creditorAccount",
    "purpose",
    "remittanceInfo"
})
public class CreditorTxnInfo {

    @XmlElement(name = "TrxId", required = true)
    protected String trxId;
    @XmlElement(name = "AmountInfo", required = true)
    protected AmountInfo amountInfo;
    @XmlElement(name = "CreditBankInfo")
    protected BankDetails creditBankInfo;
    @XmlElement(name = "Creditor")
    protected Creditor creditor;
    @XmlElement(name = "CreditorAccount")
    protected String creditorAccount;
    @XmlElement(name = "Purpose")
    protected String purpose;
    @XmlElement(name = "RemittanceInfo")
    protected String remittanceInfo;

    /**
     * Gets the value of the trxId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTrxId() {
        return trxId;
    }

    /**
     * Sets the value of the trxId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTrxId(String value) {
        this.trxId = value;
    }

    /**
     * Gets the value of the amountInfo property.
     * 
     * @return
     *     possible object is
     *     {@link AmountInfo }
     *     
     */
    public AmountInfo getAmountInfo() {
        return amountInfo;
    }

    /**
     * Sets the value of the amountInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link AmountInfo }
     *     
     */
    public void setAmountInfo(AmountInfo value) {
        this.amountInfo = value;
    }

    /**
     * Gets the value of the creditBankInfo property.
     * 
     * @return
     *     possible object is
     *     {@link BankDetails }
     *     
     */
    public BankDetails getCreditBankInfo() {
        return creditBankInfo;
    }

    /**
     * Sets the value of the creditBankInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link BankDetails }
     *     
     */
    public void setCreditBankInfo(BankDetails value) {
        this.creditBankInfo = value;
    }

    /**
     * Gets the value of the creditor property.
     * 
     * @return
     *     possible object is
     *     {@link Creditor }
     *     
     */
    public Creditor getCreditor() {
        return creditor;
    }

    /**
     * Sets the value of the creditor property.
     * 
     * @param value
     *     allowed object is
     *     {@link Creditor }
     *     
     */
    public void setCreditor(Creditor value) {
        this.creditor = value;
    }

    /**
     * Gets the value of the creditorAccount property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCreditorAccount() {
        return creditorAccount;
    }

    /**
     * Sets the value of the creditorAccount property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCreditorAccount(String value) {
        this.creditorAccount = value;
    }

    /**
     * Gets the value of the purpose property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getPurpose() {
        return purpose;
    }

    /**
     * Sets the value of the purpose property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setPurpose(String value) {
        this.purpose = value;
    }

    /**
     * Gets the value of the remittanceInfo property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRemittanceInfo() {
        return remittanceInfo;
    }

    /**
     * Sets the value of the remittanceInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRemittanceInfo(String value) {
        this.remittanceInfo = value;
    }

}
