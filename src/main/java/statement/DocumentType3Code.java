//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.3.0-b170531.0717 
//         See <a href="https://jaxb.java.net/">https://jaxb.java.net/</a> 
//         Any modifications to this file will be lost upon recompilation of the source schema. 
//         Generated on: 2019.06.13 at 04:19:56 PM CST 
//


package main.java.statement;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for DocumentType3Code.
 * 
 * <p>The following schema fragment specifies the expected         content contained within this class.
 * <p>
 * <pre>
 * &lt;simpleType name="DocumentType3Code"&gt;
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string"&gt;
 *     &lt;enumeration value="RADM"/&gt;
 *     &lt;enumeration value="RPIN"/&gt;
 *     &lt;enumeration value="FXDR"/&gt;
 *     &lt;enumeration value="DISP"/&gt;
 *     &lt;enumeration value="PUOR"/&gt;
 *     &lt;enumeration value="SCOR"/&gt;
 *   &lt;/restriction&gt;
 * &lt;/simpleType&gt;
 * </pre>
 * 
 */
@XmlType(name = "DocumentType3Code")
@XmlEnum
public enum DocumentType3Code {

    RADM,
    RPIN,
    FXDR,
    DISP,
    PUOR,
    SCOR;

    public String value() {
        return name();
    }

    public static DocumentType3Code fromValue(String v) {
        return valueOf(v);
    }

}
