package main.java.payinit;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BankAddress", propOrder = {
    "countryCode",
    "adrLine"
})
public class BankAddress {

    @XmlElement(name = "CountryCode")
    protected String countryCode;
    @XmlElement(name = "AdrLine")
    protected List<String> adrLine;

    /**
     * Gets the value of the countryCode property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCountryCode() {
        return countryCode;
    }

    /**
     * Sets the value of the countryCode property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCountryCode(String value) {
        this.countryCode = value;
    }

    public List<String> getAdrLine() {
        if (this.adrLine == null) {
            this.adrLine = new ArrayList();
        }

        return this.adrLine;
    }

}
