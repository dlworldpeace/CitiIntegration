package main.java.payinit;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

@XmlType(name = "PaymentMethod3Code")
@XmlEnum
public enum PaymentMethod3Code {

    CHK,
    TRF,
    TRA;

    public String value() {
        return name();
    }

    public static PaymentMethod3Code fromValue(String v) {
        return valueOf(v);
    }

}
