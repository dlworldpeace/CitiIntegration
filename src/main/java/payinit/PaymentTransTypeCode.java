package main.java.payinit;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

@XmlType(
    name = "PaymentTransTypeCode"
)
@XmlEnum
public enum PaymentTransTypeCode {
    FAST,
    DFT;

    private PaymentTransTypeCode() {
    }

    public String value() {
        return this.name();
    }

    public static PaymentTransTypeCode fromValue(String v) {
        return valueOf(v);
    }
}
