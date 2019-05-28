//import java.io.IOException;
//import java.io.StringReader;
//import java.io.StringWriter;
//import java.security.Key;
//import java.security.KeyStore;
//import java.security.KeyStoreException;
//import java.security.NoSuchAlgorithmException;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.security.UnrecoverableKeyException;
//import java.security.cert.CertificateExpiredException;
//import java.security.cert.CertificateNotYetValidException;
//import java.security.cert.X509Certificate;
//import java.util.logging.Level;
//import java.util.logging.Logger;
//import javax.crypto.KeyGenerator;
//import javax.xml.parsers.DocumentBuilder;
//import javax.xml.parsers.DocumentBuilderFactory;
//import javax.xml.parsers.ParserConfigurationException;
//import javax.xml.transform.OutputKeys;
//import javax.xml.transform.Transformer;
//import javax.xml.transform.TransformerException;
//import javax.xml.transform.TransformerFactory;
//import javax.xml.transform.dom.DOMSource;
//import javax.xml.transform.stream.StreamResult;
//import org.apache.xml.security.encryption.EncryptedData;
//import org.apache.xml.security.encryption.EncryptedKey;
//import org.apache.xml.security.encryption.XMLCipher;
//import org.apache.xml.security.encryption.XMLEncryptionException;
//import org.apache.xml.security.exceptions.XMLSecurityException;
//import org.apache.xml.security.keys.KeyInfo;
//import org.apache.xml.security.keys.content.X509Data;
//import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
//import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
//import org.apache.xml.security.signature.XMLSignature;
//import org.apache.xml.security.transforms.Transforms;
//import org.apache.xml.security.utils.Constants;
//import org.apache.xml.security.utils.ElementProxy;
//import org.w3c.dom.Document;
//import org.w3c.dom.Element;
//import org.xml.sax.InputSource;
//import org.xml.sax.SAXException;
//
///** Temporary class for checking the logic of signing and then encrypting a payload xml */
//
//public class SignAndEncryptionTest {
//
//  private static final String sampleBalanceInquiryPayload_Plain =
//      "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
//          + "<balanceInquiryRequest xmlns=\"http://com.citi.citiconnect/services/types/inquiries/balance/v1\">\n"
//          + "  <accountNumber>12345678</accountNumber>\n"
//          + "  <branchNumber>600</branchNumber>\n"
//          + "  <baseCurrency>USD</baseCurrency>\n"
//          + "  <accountCurrency>USD</accountCurrency>\n"
//          + "  <fromDate>2017-04-01</fromDate>\n"
//          + "  <toDate>2017-04-30</toDate>\n"
//          + "</balanceInquiryRequest>\n";
//
//  private static final String sampleBalanceInquiryPayload_Signed =
//      "<balanceInquiryRequest xmlns=\"http://com.citi.citiconnect/services/types/inquiries/balance/v1\">\n"
//          + "  <accountNumber>12345678</accountNumber>\n"
//          + "  <branchNumber>600</branchNumber>\n"
//          + "  <baseCurrency>USD</baseCurrency>\n"
//          + "  <accountCurrency>USD</accountCurrency>\n"
//          + "  <fromDate>2017-04-01</fromDate>\n"
//          + "  <toDate>2017-04-30</toDate>\n"
//          + "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
//          + "<ds:SignedInfo>\n"
//          + "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n"
//          + "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"
//          + "<ds:Reference URI=\"\">\n"
//          + "<ds:Transforms>\n"
//          + "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"
//          + "<ds:Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n"
//          + "</ds:Transforms>\n"
//          + "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n"
//          + "<ds:DigestValue>qNpHMphBwcn4f8ixKBP2Scuc4ts=</ds:DigestValue>\n"
//          + "</ds:Reference>\n"
//          + "</ds:SignedInfo>\n"
//          + "<ds:SignatureValue>\n"
//          + "1IlZa9EhfkPVEjLgHJFmeJZeyzQdKQmZrm840qns41AjyUQjDBVp4Go9/SQDB4ypifeD9sgau4kz\n"
//          + "R8a3CAnE9uYbZEf58ZpgnYbRubGlyUDJ5P5yrIiqkn+81nC7My6zd5uiRA7875n8xeumPxwRdJDM\n"
//          + "0PLnMFfVS+KLn7ftonACECDP1z6vo9wJigkCTZONCRHGxyNaNcAzyH3gnPPIeuECT3ZqXiRxdI4d\n"
//          + "UEABiVjTdC0cEUtwcFE6UW/vkaS2Xlzw1xwmi/ZoW6lxPFrd8w1qgGykVFXc7OW0ZMPvD/8DtO3W\n"
//          + "OoGC1S7Jm+1lhCRvijBpzeyiZD2OBxg/o4Mqag==\n"
//          + "</ds:SignatureValue>\n"
//          + "<ds:KeyInfo>\n"
//          + "<ds:X509Data>\n"
//          + "<ds:X509IssuerSerial>\n"
//          + "<ds:X509IssuerName>CN=Symantec Class 3 EV SSL CA - G3,OU=Symantec Trust Network,O=Symantec Corporation,C=US</ds:X509IssuerName>\n"
//          + "<ds:X509SerialNumber>97208374037470510996738722499467429663</ds:X509SerialNumber>\n"
//          + "</ds:X509IssuerSerial>\n"
//          + "<ds:X509Certificate>\n"
//          + "MIIHQTCCBimgAwIBAgIQSSGm3wMesHVSsxHYaihHHzANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQG\n"
//          + "EwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRy\n"
//          + "dXN0IE5ldHdvcmsxKDAmBgNVBAMTH1N5bWFudGVjIENsYXNzIDMgRVYgU1NMIENBIC0gRzMwHhcN\n"
//          + "MTYwMzE4MDAwMDAwWhcNMTgwMzE5MjM1OTU5WjCCASgxEzARBgsrBgEEAYI3PAIBAxMCVVMxGTAX\n"
//          + "BgsrBgEEAYI3PAIBAgwIRGVsYXdhcmUxHTAbBgNVBA8TFFByaXZhdGUgT3JnYW5pemF0aW9uMRAw\n"
//          + "DgYDVQQFEwcyMTU0MjU0MQswCQYDVQQGEwJVUzEOMAwGA1UEEQwFMTAwNDMxETAPBgNVBAgMCE5l\n"
//          + "dyBZb3JrMREwDwYDVQQHDAhOZXcgWW9yazEYMBYGA1UECQwPMzk5IFBhcmsgQXZlbnVlMRcwFQYD\n"
//          + "VQQKDA5DaXRpZ3JvdXAgSW5jLjEMMAoGA1UECwwDVFRTMUEwPwYDVQQDDDhDQ0NEZWNyeXB0UGF5\n"
//          + "bG9hZENpdGlDbGllbnREaWdpdGFsU2lnblVhdC5uYW0ubnNyb290Lm5ldDCCASIwDQYJKoZIhvcN\n"
//          + "AQEBBQADggEPADCCAQoCggEBAO0mQXzU4J+csVfopHSx6VYz8zIcMFM4shxlD0Scxvxe2hKWLEYK\n"
//          + "Uwq9viS0x5lrY6z52AQA2cg0YAhE9UBR4UEbKQcDf7BgxgwpOPn8ph/ijh4EnDUe1vZ7z6uaD7zY\n"
//          + "8NIisWaoV+5uS9BVYDGzVGl2Zdpx4Fz/KYuLvACLqRBfAqia9lMg2Xa4sF0yIsm71zgir90zPsPs\n"
//          + "WgIGO6mSoTPMnAKKja96Yp+HfSKoDWHeu03qv8LA9b62niNapega1kn8o+44KmlS0q6lNWoKIhl+\n"
//          + "IRpGNOlf0ztT2YwQx1EQ0m3KrV83qO5Deck8QEDFLkLyUhySZ5wuE8DIoDoxd9MCAwEAAaOCAxQw\n"
//          + "ggMQMEMGA1UdEQQ8MDqCOENDQ0RlY3J5cHRQYXlsb2FkQ2l0aUNsaWVudERpZ2l0YWxTaWduVWF0\n"
//          + "Lm5hbS5uc3Jvb3QubmV0MAkGA1UdEwQCMAAwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsG\n"
//          + "AQUFBwMBBggrBgEFBQcDAjBmBgNVHSAEXzBdMFsGC2CGSAGG+EUBBxcGMEwwIwYIKwYBBQUHAgEW\n"
//          + "F2h0dHBzOi8vZC5zeW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5j\n"
//          + "b20vcnBhMB8GA1UdIwQYMBaAFAFZq+fdOgtZpmRj1s8gB1fVkedqMCsGA1UdHwQkMCIwIKAeoByG\n"
//          + "Gmh0dHA6Ly9zci5zeW1jYi5jb20vc3IuY3JsMFcGCCsGAQUFBwEBBEswSTAfBggrBgEFBQcwAYYT\n"
//          + "aHR0cDovL3NyLnN5bWNkLmNvbTAmBggrBgEFBQcwAoYaaHR0cDovL3NyLnN5bWNiLmNvbS9zci5j\n"
//          + "cnQwggF+BgorBgEEAdZ5AgQCBIIBbgSCAWoBaAB3AN3rHSt6DU+mIIuBrYFocH4ujp0B1VyIjT0R\n"
//          + "xM227L7MAAABU4f5+mQAAAQDAEgwRgIhAI8gbVN9mbwJ1nDSNyRyQtZiu5yFMu+fyx8baldhPrGD\n"
//          + "AiEAzClkMwiJkkIOaCEPYAzI+SWiqwvsxMyK0ToWwqLAl7sAdgCkuQmQtBhYFIe7E6LMZ3AKPDWY\n"
//          + "BPkb37jjd80OyA3cEAAAAVOH+fqlAAAEAwBHMEUCIQCuOa40GPEGdqH/smVmo67YyQAaoP6W4oTf\n"
//          + "KHOsw35MAwIgHmrnFeWMfsy169OJ4an8v+X9RQDANsQU/qsP7m0QlPQAdQBo9pj4H2SCvjqM7rko\n"
//          + "HUz8cVFdZ5PURNEKZ6y7T0/7xAAAAVOH+fqkAAAEAwBGMEQCIB2nJ9IOfKZInrdwwyFi/Y1Fkd6H\n"
//          + "Kc+1A0ZSLOI+3/QPAiAMXw7ii603WUITvibgcWrrUPtjQr/fMxbrmxxPRWcI/TANBgkqhkiG9w0B\n"
//          + "AQsFAAOCAQEAP2w+Uxa+Ck79iispyCPntW627A4yuef+PpVJX/mUDQRmmwA32W4V4OAABO4QoWNo\n"
//          + "nIwuwxARAM0+86oeTKly9KTBUsmL5GFHLXURdayVMsohIUlgwIM/JimiVN6KCrcDY0xgGpPiTIL4\n"
//          + "ZonsarHgvmbulOOXv/qQbbToVvqVjpB7y4upfYqAiF62ngOEjWfXa19Gxw6UXmht1j94oyimCYrI\n"
//          + "3GZbVGItKLIrmhib7FQe1cJI1uqNp6oUODDM0+eMXlIeJ/CTBOBf0Y1E4dR6WP3AZ3kD8bPDpOva\n"
//          + "g+euTfkYDPTOdnjWGHFPSlPhhCTaP7K1fdokhLVftDYe9TCjkw==\n"
//          + "</ds:X509Certificate>\n"
//          + "</ds:X509Data>\n"
//          + "</ds:KeyInfo>\n"
//          + "</ds:Signature></balanceInquiryRequest>";
//
//  private static final String sampleBalanceInquiryPayload_SignedEncrypted =
//      "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n"
//          + "<xenc:EncryptedKey><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><xenc:CipherData><xenc:CipherValue>IWhnOsfaOlUm862ZCIxWEZ635+xk9iIG58faFzwR9seVeRsu6x9tYhOgCnplf8g9T6vQy7zeLpGD\n"
//          + "O/9lBrOh/MRFLnaMMcaldclFsMNxjDtTLTqwbcTkyA18h4upgFMQ31Ym1jufcnQ4tGYkW+zBG23i\n"
//          + "OY764/iuY8ExoMxt0h9lr9YOlnFLkHknTO41tZD6xF4FI+C83IxKJF0mHBth8N+QUUyHIILF7vGe\n"
//          + "ZYDxExFBza01GHG4nVScwkkY5UrIbWZgayz2ncmI28Z5Yz+tgiZ1KuQ5nknAjzBxShxzLAdgH3q0\n"
//          + "YrFvY9qZbdOzTpeUtXeXOFtgNQQ+YJEY4ohw+g==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>i358Y2SGtARfapeqM1h3gRRJrY3EHwuqsTvRaTddq2d/GYXeA3uaQWGbxdaldyU/gByKH/G8Elj9\n"
//          + "+9T/dZJ8Nv3u5K3DMbolPRv3E4b3YD+7+mXxHMPhHFn8A9hheA2Nk4TRvVTgsiKBSZ0vggcG8sNZ\n"
//          + "hkCTrwxMvhtzVUpudasBF3X8t/h0k5KGBR8/W6Y+zGWgAsGCp8V9vw8O+6vXwrHMu/C3+nzo29CJ\n"
//          + "mRBNkHEi6xO8NZPIU/uzXzrVjr7b/KWEWgWoWN22vpxQEoHoWFRVI91XGjxoUG7K1lMSX/xqJyt7\n"
//          + "sviCn3egPGCYerOzpUJuJwvd8n8GkaHPHZhpC+5gyiWPfLkuO0D8ecvny2i9cAUeQIAfa/RUst05\n"
//          + "IY0SeO8wmWQ3T4cinm4akkDnkjZLii+dqAPyrU4YgObY7rQay06cn8dL3BdsDv2fN5NPxEqQMpK4\n"
//          + "gctVZDU/31MdWYrYPmyEZX/UubBpozizPbn+0TjVO2jOtOQMkeXaDRzVhwrV0SAcAbu0P0ldhrGz\n"
//          + "neTqQl+ji9JE7JII/NgN6NAFzLzpqieFFJVg4KY3SUTxSSbv1er73jUo7+N2mXj/+HI6Zb7Ucmq+\n"
//          + "2WRo/xPxrmnbwyjR3v98W5UdUU8+InGPrKbmbQ9svauvBCA6YxWhXLyWjAJvnxETLw3RZ+MqlzLJ\n"
//          + "cSAnE/RNgdEtMMWiR9ucj4OA+RXKw0Re5x87tHeqA40cIoeaMGvNNYgY8CABqqEH6NSn3oKIcrHo\n"
//          + "9oYXbbJ3rpQzZi8Ssqs5URCKZ8XzLteeKNE2RxI2Nrpwg8vX01BMuvyzr+mbR1mFvUyNyVdDsF6O\n"
//          + "tD+RLcFy1pcTaa+O2c4jNlxaCGbCLq37yQV/EJNA0mLpM71+E9v0utQbdUFeANf3Zzc0Nk1fdqSp\n"
//          + "bexgjchSDz2RicaFGOC0XfPs/OlqHk8qwJw0JS45kqH43NGnqMxZATZWKDXctkTB5qJohyNAwFrB\n"
//          + "crAX94l/vQ8RZ8eA+d14Wsa2zt7KirlLBZZiXx4Hp2fzXV89Cxo4Sk2hMUljpBX+0ZHoObNOJmEZ\n"
//          + "h25UFlr3+GwDsnBAHcru4loaeX4OPSdsvIyTSgRHEK6OCx5rCh4m134dRDtWvEvlqtAb8vTnUjK/\n"
//          + "7LFhmZ7W9l8/8nLcGKyG9VYik80WR8gIyua9ZJ0McwRfPJNsO56eIXI78klvlIOYXaIb+DISWbkd\n"
//          + "dSS5e1X8z8uhJ2adblyf74pDiAqQxVR58C9T9/jP0zzO4TNJAcxsFbuS0gH/4BC4fsVuJb8+uQ7t\n"
//          + "FfwqfvVmjS2dNl9R4Do0lvFM2+DduF84ckhF3MB3I50Lksq4zvy9ucYo7P1P035HheYSw90GYW6u\n"
//          + "XePKty86/5IxIn+rJPru/AduKTssR8RhDq+pq3umLcZ9jLuEbyTyk8ZqcBDuLFsn/KBfBictNbsi\n"
//          + "bVvU5jea92M4L07Yw68YFZxsaY+nujbOPMHLBjxIn98X+cOHwGbdlGvb8W+qgba7h1OfBVZLTVzS\n"
//          + "xNJhFF/AszKnXqX3n70JSlVlYFdc4aQH0dIOZ3Jed84voreqV16a8xw3K0AW1YJUv/ZGQGexnQBo\n"
//          + "O+KdhB3oWeluSTg4wg1Rvoz83+ONSgUFhtywW4z9qWzHD/FzqK8plfzLkNwhVyw5EtAO2/91h2ML\n"
//          + "roB10vdHIaSwwjNUT3odLaI6s9y7KYF7wyVhHLCAPjoWkXi+mpVCePMmh0+nYgcDCn/lAnfwpaOK\n"
//          + "lqpKQg4U6gbMpbejr+fwuEz9OgejeGq/xRpTgY3EufNxwYoTMOrWJc58IMyi7s7ScQX6mAIoIv3Q\n"
//          + "/5Hq6aoBBdIZTm02yGI7f59ObnLDOVCUuYc8yaZWlw+Q7m9UFDJGICDXJlmBgUVA48Dfd0hwWgGn\n"
//          + "8DmJ1ljyJZo9hH3ywUlQIZ4kSXQG/9Hi8xnsM0iJGHf9JwvkXBCizdzfTXinc5u/Yj+hb9GKFNJD\n"
//          + "1Oo0WPobnIIzjbl+zc1O/JUWXe/Uba1N0xg+PLAJdoDPuHpQ5YO9rOy6Emg2WH/t0X7hI31Z/SdG\n"
//          + "hUx5gSw4Wp730qJ0e0mJwzvAlfBC0MN8Ee9Iqhc3aIpIDQwMzHzvo6fGKPmVxzGKoIHBNX5I08MK\n"
//          + "4vYAPAghtW9AIOlv4do6xm4JZ3Ln1Jsky/+t3y0Ovdf9hdB0i71JOIZmsaqre2b25hg+A/g5t48b\n"
//          + "vF0F0HRsgPeQfm62/o+2gKBxm4xKHu3uh9VruT5jwHW2bea96fg9hWChEkXgTAm3T6MrT8IKbo3W\n"
//          + "W33IBnZH1AyQmhb0NYieiLlxV10C98Qg3+QLvl7oi7TNVZTfktPWC58O/FO306kl9J4VM2isStks\n"
//          + "ktqbBJpGQhHLJRfTy0hmVBYW8a1eQ1JWOINlomBLkbA7BNj6zJHQktsBqo+cNGLPQypR7Iki/E32\n"
//          + "RhiyYVxcpW/s+LNjJHd5BZcDNyoJsPceRJnwcKu70tizVC7N7DIHnqxH97Au9f+mXW/BUBFc7xAI\n"
//          + "3qn2HezdBGZ9YMO/UsiKq2gUN0KwHLNd23EJAcnEc5UxnUGDNIP/g0HlZjOCm97kMY9QgUbuMg9b\n"
//          + "GLUAB7ttX9fJcYEJ4CLQcojMjq9y03nozBlk8jHreKq9REDKrKPdinKduaulPAYHlw5hRn8fVYrM\n"
//          + "qAZ7OXynrZT+3FLd15+I0ASivp/6+mVyFIpcd+E20mN+ULlAuOnFCV9K91db0sSy5CwSz+Z1fbcv\n"
//          + "XKfIeE+CHDm2f8HuOzm30Qd2RW0LPYRZk5qpIi8xSO0+w+y9Rw8Yh/ntrWseiW3h2JeEMdOBWqi8\n"
//          + "HyxlNAYIZMYJfAyIyuuc67ceCCKeh1L976svtG2EEHLxhY1qlB/INChPm2qvQKW36kfrOA5Dp4n6\n"
//          + "wFXlVT6XhGlyjB4qnKgjFStDSY0C95u6DLi1RfcuMYSHNTsEwaYC7vHHpEILiDesAGeiqJYtffA/\n"
//          + "854q5ljv738PpWm+idLhl3pnZEmZlPF0LKCHEwh/fGTlelJ7XpXaGEmCw/QpPUEzOZzopSzaIlgL\n"
//          + "EyaaywIvPzDaQ3szJhDxqJqiC/kQQBCwbOSAH91UsQnZDHeQQ24ei+a28Le6vvxt/KIyf5pTBbQU\n"
//          + "yjwFxp8LKF3hU7jscModlGUDav0Xl1JFZ0n+7qTYXpf3YjIYnea5sca52glhBfbBcA4Tf9AqEoY5\n"
//          + "r1mz/bjim8n1lgZJoOb0c3pW0EKW7v3HP0MV9bj/peszdftk3GzAAPRS/iYyOoEQgniBUsIelDsg\n"
//          + "EcVlmWrjgXhUC8btH4t/ELLo/vx5ANi2fLvJr3AWaJZZ0vDkw+BUPkHZ3U+kFyNt2jTIxbJN/J9n\n"
//          + "CuEyI8qKPnxc7z3xmizXdluBMHf1HagE9sxAahcVDJQFaAV74Jdb3JV0xW6LTezz2wqRhBjSHxX/\n"
//          + "NuBXrYmq9ptW+71WIO3TIUlHXeVuZB6DXCeb58dlc3p1e5ZmCFb0DsdGITrle3rQWcATLf48hcLT\n"
//          + "OXr7xcF2Fd/Oy97kn7zfcjhGOFlWFwBkAlHXl97gF0/cOWsh96c1uo1WleaL8OdMMEK2rKj5kyZq\n"
//          + "rbOacP5ornNzSX4tcPELQW3Ragjnc6u0Sln/9Z/6ZQqe1DUGNEMeHqku47RA7hFRk1E2HZiIYCX9\n"
//          + "RWlmUdp2ozCjBQvEHY9QooJh4zLHQRTyNIf4rEjddDgSTmtykclF9PLv5SMLdZ00cQAR5K5/7ylH\n"
//          + "LkOSmnG+YAX9Vu9CLEwFuimBDX0V46SebQTSBF8chVHPNX/2tjt1DqQAxPgOnZKYjA1A7XXt/hnM\n"
//          + "EsA/qcQ9PaDfVmQZzBtyzlREHsnDOcAjYNBYYBCG+s5b0+t9PXfAaz+cc6zDq9+RJEQ4jVLGa5L0\n"
//          + "ij4jtMJRTnHkgDnC64xv+gjfuUDhSrswz5qRiY4ZlcHVoslUf3ePtQJVXiGaDNygiob7dHtZ7esB\n"
//          + "AqeZe+gPhk/ebKiUQHhiGquVlJMqKDx66pVHN/T8ma6kBapxsW6/9WYEcZw9F1eAWXKzWSgHISC0\n"
//          + "iI+naQijL7F8wTEm/H1E+RawALdR9W/dx8qYy61Xofj7494A1f12bD9jx3fu7/GmbYXx0DOtnagM\n"
//          + "q1JIy+vc6aUq329IiHBaiImB0TEO+DLpXia8WKE+VlNLdWtAdsgQDRvncPJNBEbNlnmry5Wmb/Al\n"
//          + "ongZ7mkpXoU7N0gxSv6Z4DFy/CCzoJwZBQH/rQyQ0+o4zvDmMyLLWduR7agtvlaiOlt+fl7/0ZzT\n"
//          + "C86MWUnkOmc3TqCci/M3VD/d6PZc1UR5nenqYLbdb5EamWy2gH+pdc5NZoQ4Rs8HmNoyNV1gYPQL\n"
//          + "stVuHSehelBTSqwoVuAPih3VFZF6Y7vdUWe5+s6awQWRuy5X4+ie26NkVN7E6YZQJTTfK8prmUXQ\n"
//          + "nimDzHTGoGuavlVem2wpnAXQZnOJO8VOxZzjhY1KpUPAenzGzuCn4B0FDEhsRwDp45jDPCqjpbD0\n"
//          + "W+Tl+juXALuCBLEiX8kdl3NONPEAuhjNplkHldxYTEJNLUN/edAfZFthX5YwaCCqpMKQxPhWmwiB\n"
//          + "DKU0C60gmDYHB25pAoPwtayYIlRQ83SX7gbWtzMJxSMv7ony0FDYAvnCVeDbU3tBrBsCEajLZNXU\n"
//          + "OX0OQiugl7DJ2FvxtfWl2oqWljnfxTSNttvvQlifrVxTJJ6GxqcsQqCZdMpsoLoTv/cKI/0BiO/N\n"
//          + "kTBJ2dmwfyE7kAakGz+4mGl9cimjC3mMV9MEylOdt9C3TTtI8GMCZrsNFh0EvMvWP2QHIbTcR+4I\n"
//          + "FHlZtIAe5iF+f/rWJKyy1as6xiFNe4B8r8BzpDi9KODEFYoRSeosxZSFcb/geP2sVHRKcM29W9Lr\n"
//          + "VDHsPLPLiDBwDh/QiSdjHyzI96LNv30CvckN7GUtIQlj4uY+a1sSdvDn7Fma3xu70Xz87SM3VenZ\n"
//          + "zYka6TqkykcgTMnvnp5Bs2njSmXeohAUswntKSMfzKzDjwSUEgzqtdeh15JXx1nlc0FUZb8ekY3a\n"
//          + "/AM4St8JiymHf0Jf1YvJe2NNzNFSz+vmbeQPvFcoqhwKREfg8LurPNhuIgQ9VL0BoYtscIx1YBza\n"
//          + "A5SXKcGPX/MUD29PToIG4PWIvwcfYkmk2mTjSzcG0sFhLn1MJjo+eQJh3tyI4G77B9FG9iXkUB42\n"
//          + "FrCHYA/lY3voX7Smz5ns01KMUfkhS030wkGgJRlUc1UKpC9PRSWnbyRAYKPWcCboOgslBE3TXW+I\n"
//          + "CNNd0LVsDqveOveGXZLRYbR24nR4G72O3Ctmym9DHqPDDvsAl6NdePkBlAJyRLj1o5FMqXML2AP8\n"
//          + "+YFhWyb2x9J36jrWxOI+/xcL1dHOIDGWserFyEH3wmMp5cTzpEEVY6gvwEWpheIBQ+ljwkgJo1Hd\n"
//          + "+jh/vAOamLISLTWXwdjeV3D6yAmgf1WAAZ/WmBdFiueak7KguDThDmUO0udqRP2AvBFzmxhUXsO/\n"
//          + "ItmWmG7FGASEQHl7VrvguWkgO0L3dWf+P3hPM12ajl7NyhwuD9dlwXY25hJ7Rvj6a/xM4C7CTjp4\n"
//          + "oHFMxx4kHEPwtFh2UGoVOl/RuNEmxpR/QUFO2b/1QQqg2ejawOyiQ8CZpQE/5WqJSaBCEWDDKBCh\n"
//          + "NSqa677LdPhaVi32bYU1BzXlc+6mXtIyhkZU64CtynKauaE4gGSxHgyvJ2PBYRoNUCRiauwHfqyH\n"
//          + "LFkEZHGNIj05eZatuU4wNUHlq/SFuRuwaVtm92FB/T16IOm4bHs2QMnrkulx4hMFkLCDaVP/uNFf\n"
//          + "dufK/w==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>";
//
//  private static final String sampleBalanceInquiryResponse_Encrypted =
//      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
//          + "<xenc:EncryptedData Type=\"http://www.w3.org/2001/04/xmlenc#Element\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\"/><dsig:KeyInfo xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey Recipient=\"name:2651a0c7-24bf-4478-932f-8d1de7fdb472\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><dsig:KeyInfo><dsig:KeyName>2651a0c7-24bf-4478-932f-8d1de7fdb472</dsig:KeyName></dsig:KeyInfo><xenc:CipherData><xenc:CipherValue>eWYT1VhmDvCIBlrT+/Fc5/Lu3WHWGe1ZYlKnRDpxoTwPHCs3PwR+hDg8SI+Td1qAlxVVYrkLpBWQjuXullemIhyU77RRfIXeLTym5sGegu84OULxsnEXDEUix0F2Sg6Tr9FqIPn3Ap2P2xRuHFwgAkXm7Q96o1RDJCW8HYF130Kx1iohKiuxdRTExTxR9knOeI47boNAN3k0UTzkz3GNVBNf7AM43EHNemsXp+iZ5fJNyHruSqwChyeK0Zp/Z5Fl67PWX2iFdBqmc0MEM/DrbJZXzA4SXQwwsACWnSjUDAF43mXqsqmh7F2e167JKzJNUO0kJiZaTHAoTIcBz34hjA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo><xenc:CipherData><xenc:CipherValue>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</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>";
//
//  private static final String sampleBalanceInquiryResponse_Plain =
//      "<Document xmlns=\"urn:iso:std:iso:20022:tech:xsd:camt.052.001.02\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><BkToCstmrAcctRpt><GrpHdr><MsgId>CITIBANK/20170509-PSR/1956706383</MsgId><CreDtTm>2017-05-09T13:48:11</CreDtTm><MsgRcpt><Nm>8010012 262X XXXXXX XXX</Nm><Id><OrgId><Othr><Id>8012345678</Id></Othr></OrgId></Id></MsgRcpt></GrpHdr><Rpt><Id>12345678</Id><CreDtTm>2017-05-09T13:48:11</CreDtTm><Acct><Id><Othr><Id>GB27CITI18500812345678</Id></Othr></Id><Ccy>USD</Ccy><Nm>8010012 262X XXXXXX XXX</Nm><Ownr><Nm>8010012 262X XXXXXX XXX</Nm></Ownr><Svcr><FinInstnId/><BrnchId><Id>600</Id><Nm>CITIBANK NA LONDON</Nm></BrnchId></Svcr></Acct><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-03T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-03T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-03T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-03T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-04T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-04T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-04T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-04T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-05T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-05T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-05T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-05T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-06T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-06T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-06T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-06T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-07T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-07T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-07T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-07T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-10T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-10T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-10T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-10T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-11T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-11T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-11T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-11T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-12T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-12T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-12T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-12T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-13T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-13T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\"/><CdtDbtInd/><Dt><DtTm>2017-04-13T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-13T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-14T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-14T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-14T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-14T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-17T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-17T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-17T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-17T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-18T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-18T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-18T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-18T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-19T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-19T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-19T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-19T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-20T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-20T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\"/><CdtDbtInd/><Dt><DtTm>2017-04-20T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">-3.00</Amt><CdtDbtInd>DBIT</CdtDbtInd><Dt><DtTm>2017-04-20T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\"/><CdtDbtInd/><Dt><DtTm>2017-04-21T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-21T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">-3.00</Amt><CdtDbtInd>DBIT</CdtDbtInd><Dt><DtTm>2017-04-21T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-21T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-24T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-24T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-24T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-24T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-25T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-25T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-25T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-25T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-26T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-26T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-26T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-26T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-27T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-27T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\"/><CdtDbtInd/><Dt><DtTm>2017-04-27T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-27T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-28T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-28T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>OPAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\"/><CdtDbtInd/><Dt><DtTm>2017-04-28T00:00:00</DtTm></Dt></Bal><Bal><Tp><CdOrPrtry><Cd>CLAV</Cd></CdOrPrtry></Tp><Amt Ccy=\"USD\">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><DtTm>2017-04-28T00:00:00</DtTm></Dt></Bal><TxsSummry><TtlNtries><TtlNetNtryAmt>0.00</TtlNetNtryAmt></TtlNtries><TtlCdtNtries><NbOfNtries>4</NbOfNtries><Sum>5207.12</Sum></TtlCdtNtries><TtlDbtNtries><NbOfNtries>4</NbOfNtries><Sum>5207.12</Sum></TtlDbtNtries></TxsSummry></Rpt></BkToCstmrAcctRpt></Document>";
//
//  /**
//   * Getting the XML payload as Document object
//   *
//   * @param xmlPayload original payload in xml format
//   * @return converted document object
//   * @throws HandlerException custom exception for Handler class
//   */
//  private static Document convertXMLPayloadToDoc (String xmlPayload)
//      throws HandlerException {
//
//    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
//    factory.setNamespaceAware(true);
//    try {
//      DocumentBuilder builder = factory.newDocumentBuilder();
//      return builder.parse(new InputSource(new StringReader(xmlPayload)));
//    } catch (ParserConfigurationException | IOException | SAXException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//
//  /**
//   * Getting public client signing key
//   *
//   * @return client public key
//   * @throws HandlerException custom exception for Handler class
//   */
//  private static X509Certificate getClientPublicKey () throws HandlerException {
//    try {
//      KeyStore ks = KeyStore.getInstance("JKS");
//      X509Certificate signCert = (X509Certificate) ks
//          .getCertificate(HandlerConstant.clientSignKeyAlias);
//      signCert.checkValidity();
//      return signCert;
//    } catch (CertificateNotYetValidException | CertificateExpiredException |
//        KeyStoreException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//
//  /**
//   * Getting private client signing Key
//   *
//   * @return PrivateKey client private key
//   * @throws HandlerException custom exception for Handler class
//   */
//  private static PrivateKey getClientPrivateKey () throws HandlerException {
//    try {
//      KeyStore ks = KeyStore.getInstance("JKS");
//      return (PrivateKey) ks.getKey(
//          HandlerConstant.clientSignKeyAlias, HandlerConstant.keyStorePwd.toCharArray());
//    } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//
//  /**
//   * Signing the XML payload document
//   *
//   * @param xmlDoc xml document to be signed
//   * @param signCert certificate to be added in
//   * @param privateSignKey private key used to sign the document
//   * @throws XMLSecurityException if an unexpected exception occurs while signing
//   *                              the {@code xmlDoc}
//   */
//  private static void signXMLPayloadDoc (Document xmlDoc, X509Certificate signCert,
//      PrivateKey privateSignKey) throws XMLSecurityException {
//    org.apache.xml.security.Init.init();
//    ElementProxy.setDefaultPrefix(Constants.SignatureSpecNS, "ds");
//    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
//    dbf.setNamespaceAware(true);
//    Element root = xmlDoc.getDocumentElement();
//    XMLSignature sig = new XMLSignature(xmlDoc, "file:",
//        XMLSignature.ALGO_ID_SIGNATURE_RSA);
//    root.appendChild(sig.getElement());
//    Transforms transforms = new Transforms(xmlDoc);
//    transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
//    transforms.addTransform(Transforms.TRANSFORM_C14N_OMIT_COMMENTS);
//    sig.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);
//    KeyInfo info = sig.getKeyInfo();
//    X509Data x509data = new X509Data(xmlDoc);
//    x509data.add(new XMLX509IssuerSerial(xmlDoc, signCert));
//    x509data.add(new XMLX509Certificate(xmlDoc, signCert));
//    info.add(x509data);
//    sig.sign(privateSignKey);
//  }
//
//  /**
//   * Getting public citi encryption key
//   *
//   * @return citi public key
//   * @throws HandlerException custom exception for Handler class
//   */
//  private static PublicKey getCitiPublicKey () throws HandlerException {
//    try {
//      KeyStore ks = KeyStore.getInstance("JKS");
//      X509Certificate encryptCert = (X509Certificate) ks
//          .getCertificate(HandlerConstant.citiEncryptKeyAlias);
//      encryptCert.checkValidity();
//      return encryptCert.getPublicKey();
//    } catch (CertificateNotYetValidException | CertificateExpiredException |
//        KeyStoreException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//
//  /**
//   * Encrypt the signed XML payload document
//   *
//   * @param signedXmlDoc signed XML document
//   * @param publicEncryptKey public key used to encrypt the doc
//   * @throws XMLEncryptionException if an unexpected exception occurs while
//   *                                encrypting the signed doc
//   * @throws HandlerException custom exception for Handler class
//   */
//  private static Document encryptSignedXMLPayloadDoc (Document signedXmlDoc,
//      PublicKey publicEncryptKey) throws XMLEncryptionException, HandlerException {
//
//    String jceAlgorithmName = "DESede";
//    Key symmetricKey;
//
//    try {
//      KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
//      symmetricKey = keyGenerator.generateKey();
//    } catch (NoSuchAlgorithmException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//
//    String algorithmURI = XMLCipher.RSA_v1dot5;
//    XMLCipher keyCipher = XMLCipher.getInstance(algorithmURI);
//    keyCipher.init(XMLCipher.WRAP_MODE, publicEncryptKey);
//    EncryptedKey encryptedKey = keyCipher
//        .encryptKey(signedXmlDoc, symmetricKey);
//    Element rootElement = signedXmlDoc.getDocumentElement();
//    algorithmURI = XMLCipher.TRIPLEDES;
//    XMLCipher xmlCipher = XMLCipher.getInstance(algorithmURI);
//    xmlCipher.init(XMLCipher.ENCRYPT_MODE, symmetricKey);
//    EncryptedData encryptedData = xmlCipher.getEncryptedData();
//    KeyInfo keyInfo = new KeyInfo(signedXmlDoc);
//    keyInfo.add(encryptedKey);
//    encryptedData.setKeyInfo(keyInfo);
//
//    try {
//      return xmlCipher.doFinal(signedXmlDoc, rootElement, false);
//    } catch (Exception e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//
//  /**
//   * Convert the Document object to String value
//   *
//   * @return string value of the document
//   * @throws HandlerException custom exception for Handler class
//   */
//  private static String convertDocToString (Document xmlDoc) throws HandlerException {
//    try {
//      TransformerFactory tf = TransformerFactory.newInstance();
//      Transformer transformer = tf.newTransformer();
//      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
//      StringWriter writer = new StringWriter();
//      transformer.transform(new DOMSource(xmlDoc), new StreamResult(writer));
//
//      // TODO check what kind of string value is returned: XML?
//
//      return writer.getBuffer().toString();
//    } catch (TransformerException e) {
//      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
//      throw new HandlerException(e.getMessage());
//    }
//  }
//
//  /**
//   * Sign xml payload using our private key and citi cert, followed by encrypting
//   * it using citi public key
//   *
//   * @param payloadXML payload string in xml
//   * @return encrypted signed payload string
//   * @throws XMLSecurityException if an unexpected exception occurs while signing
//   *                              the auth payload or encrypting the payload
//   * @throws HandlerException custom exception for Handler class
//   */
//  private static String signAndEncryptXML (String payloadXML)
//      throws XMLSecurityException, HandlerException {
//    Document payloadDoc = convertXMLPayloadToDoc(payloadXML);
//    PrivateKey clientPrivateKey = getClientPrivateKey();
//    X509Certificate clientSigningCert = getClientPublicKey();
//    signXMLPayloadDoc(payloadDoc, clientSigningCert, clientPrivateKey);
//    PublicKey citiPublicKey = getCitiPublicKey();
//    Document encryptedSignedXMLPayloadDoc = encryptSignedXMLPayloadDoc(
//        payloadDoc, citiPublicKey);
//    return convertDocToString(encryptedSignedXMLPayloadDoc);
//  }
//
//  public static void main (String[] args) {
//    try {
//      String sampleBalanceInquiryPayload_SignedEncrypted = signAndEncryptXML(
//          sampleBalanceInquiryPayload_Plain);
//      System.out.println(sampleBalanceInquiryPayload_SignedEncrypted);
//    } catch (XMLSecurityException | HandlerException e) {
//      e.printStackTrace();
//    }
//  }
//}
