package main.java.payinit;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BankInfo", propOrder = {
    "bic",
    "name",
    "address"
})
public class BankInfo {

    @XmlElement(name = "BIC")
    protected String bic;
    @XmlElement(name = "Name")
    protected String name;
    @XmlElement(name = "Address")
    protected BankAddress address;

    /**
     * Gets the value of the bic property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getBIC() {
        return bic;
    }

    /**
     * Sets the value of the bic property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setBIC(String value) {
        this.bic = value;
    }

    /**
     * Gets the value of the name property.
     *
     * @return
     *     possible object is
     *     {@link String }
     *
     */
    public String getName() {
        return name;
    }

    /**
     * Sets the value of the name property.
     *
     * @param value
     *     allowed object is
     *     {@link String }
     *
     */
    public void setName(String value) {
        this.name = value;
    }

    /**
     * Gets the value of the address property.
     * 
     * @return
     *     possible object is
     *     {@link BankAddress }
     *     
     */
    public BankAddress getAddress() {
        return address;
    }

    /**
     * Sets the value of the address property.
     * 
     * @param value
     *     allowed object is
     *     {@link BankAddress }
     *     
     */
    public void setAddress(BankAddress value) {
        this.address = value;
    }

}
