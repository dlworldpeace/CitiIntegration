package main.java.payinit;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "InitiatePayments", propOrder = {
    "paymentHeader",
    "paymentInfo"
})
public class InitiatePayments {

    @XmlElement(name = "PaymentHeader", required = true)
    protected PaymentHeader paymentHeader;
    @XmlElement(name = "PaymentInfo", required = true)
    protected List<PaymentInfo> paymentInfo;

    /**
     * Gets the value of the paymentHeader property.
     * 
     * @return
     *     possible object is
     *     {@link PaymentHeader }
     *     
     */
    public PaymentHeader getPaymentHeader() {
        return paymentHeader;
    }

    /**
     * Sets the value of the paymentHeader property.
     * 
     * @param value
     *     allowed object is
     *     {@link PaymentHeader }
     *     
     */
    public void setPaymentHeader(PaymentHeader value) {
        this.paymentHeader = value;
    }

    /**
     * Gets the value of the paymentInfo property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the paymentInfo property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getPaymentInfo().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link PaymentInfo }
     * 
     * 
     */
    public List<PaymentInfo> getPaymentInfo() {
        if (paymentInfo == null) {
            paymentInfo = new ArrayList<>();
        }
        return this.paymentInfo;
    }

}
