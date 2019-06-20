package main.java.payinit;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CreditorTxnInfo", propOrder = {
    "txnId",
    "amountInfo",
    "creditorBankInfo",
    "creditor",
    "creditorAccount",
    "purpose",
    "remittanceInfo"
})
public class CreditorTxnInfo {

    @XmlElement(name = "TxnId", required = true)
    protected String txnId;
    @XmlElement(name = "AmountInfo", required = true)
    protected AmountInfo amountInfo;
    @XmlElement(name = "CreditorBankInfo")
    protected BankInfo creditorBankInfo;
    @XmlElement(name = "Creditor")
    protected Party creditor;
    @XmlElement(name = "CreditorAccount")
    protected String creditorAccount;
    @XmlElement(name = "Purpose")
    protected String purpose;
    @XmlElement(name = "RemittanceInfo")
    protected String remittanceInfo;

    /**
     * Gets the value of the txnId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getTxnId() {
        return txnId;
    }

    /**
     * Sets the value of the txnId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setTxnId(String value) {
        this.txnId = value;
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
     * Gets the value of the creditorBankInfo property.
     * 
     * @return
     *     possible object is
     *     {@link BankInfo }
     *     
     */
    public BankInfo getCreditorBankInfo() {
        return creditorBankInfo;
    }

    /**
     * Sets the value of the creditorBankInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link BankInfo }
     *     
     */
    public void setCreditorBankInfo(BankInfo value) {
        this.creditorBankInfo = value;
    }

    /**
     * Gets the value of the creditor property.
     * 
     * @return
     *     possible object is
     *     {@link Party }
     *     
     */
    public Party getCreditor() {
        return creditor;
    }

    /**
     * Sets the value of the creditor property.
     * 
     * @param value
     *     allowed object is
     *     {@link Party }
     *     
     */
    public void setCreditor(Party value) {
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
