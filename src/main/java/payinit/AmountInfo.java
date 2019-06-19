package main.java.payinit;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AmountInfo", propOrder = {
    "instdAmt"
})
public class AmountInfo {

    @XmlElement(name = "InstdAmt")
    protected Amount instdAmt;

    /**
     * Gets the value of the instdAmt property.
     * 
     * @return
     *     possible object is
     *     {@link Amount }
     *     
     */
    public Amount getInstdAmt() {
        return instdAmt;
    }

    /**
     * Sets the value of the instdAmt property.
     * 
     * @param value
     *     allowed object is
     *     {@link Amount }
     *     
     */
    public void setInstdAmt(Amount value) {
        this.instdAmt = value;
    }

}
