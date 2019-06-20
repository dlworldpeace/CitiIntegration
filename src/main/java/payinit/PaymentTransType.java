package main.java.payinit;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PaymentTransType", propOrder = {
    "serviceLvlCode",
    "localInstrmtCode"
})
public class PaymentTransType {

    @XmlElement(name = "ServiceLvlCode")
    protected String serviceLvlCode;
    @XmlElement(name = "LocalInstrmtCode")
    protected String localInstrmtCode;

    /**
     * Gets the value of the serviceLvlCode property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getServiceLvlCode() {
        return serviceLvlCode;
    }

    /**
     * Sets the value of the serviceLvlCode property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setServiceLvlCode(String value) {
        this.serviceLvlCode = value;
    }

    /**
     * Gets the value of the localInstrmtCode property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getLocalInstrmtCode() {
        return this.localInstrmtCode;
    }

    /**
     * Sets the value of the localInstrmtCode property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setLocalInstrmtCode(String value) {
        this.localInstrmtCode = value;
    }
}
