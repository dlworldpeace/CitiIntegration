package main.java;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMResult;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.eclipse.persistence.jaxb.JAXBContextProperties;

/**
 * This API supports all conversions between XML and Json via Format classes
 * generated using .xsd files.
 *
 * @author Sagar Mahamuni and Xiao Delong.
 * @version 1.0
 * @since 2019-06-12.
 */

public class BankFormatConverter<T> {

  private String classPath;

  public BankFormatConverter(String classPath) {
    this.classPath = classPath;
  }

  /**
   * Convert {@code XMLStr} in standard ISO format such as camt.053.001.02 to
   * a JAXBElement of rootElement fixed as Document type.
   *
   * @param XMLStr XML String in standard ISO format.
   * @return a JAXBElement of a standard ISO format.
   * @throws JAXBException if an unpexted event happens during the conversion.
   */
  public JAXBElement<T> readXMLToElement (String XMLStr) throws JAXBException {

    JAXBContext jaxbContext = JAXBContext.newInstance(classPath);
    Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
    StringReader reader = new StringReader(XMLStr);
    return (JAXBElement<T>) unmarshaller.unmarshal(reader);
  }

  /**
   * Convert a JAXBElement of {@code rootElement} rooted at Document type to a
   * XML String of its corresponding standard ISO format such as camt.053.001.02.
   *
   * @param rootElement JAXBElement rooted at Document Element.
   * @return corresponding XML String.
   * @throws JAXBException if an unpexted event happens during the conversion.
   * @throws TransformerException if an unpexted event happens when adding some
   *                              property to the string styles.
   */
  public String writeElementToXML (JAXBElement<T> rootElement) throws JAXBException,
      TransformerException {

    JAXBContext jaxbContext = JAXBContext.newInstance(classPath);
    Marshaller marshaller = jaxbContext.createMarshaller();
    OutputStream out = new ByteArrayOutputStream();
    DOMResult domResult = new DOMResult();
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
    marshaller.marshal(rootElement, domResult);
    Transformer transformer = TransformerFactory.newInstance().newTransformer();
    transformer.setOutputProperty(OutputKeys.DOCTYPE_PUBLIC, "yes");
    transformer.setOutputProperty(OutputKeys.ENCODING, "utf-8");
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    transformer.setOutputProperty(
        "{http://xml.apache.org/xslt}indent-amount", "2");
    transformer.transform(new DOMSource(domResult.getNode()), new StreamResult(out));
    return out.toString();
  }

  /**
   * Convert a JAXBElement of {@code rootElement} rooted at Document type to a
   * JSON String of its corresponding standard ISO format such as camt.053.001.02.
   *
   * @param rootElement JAXBElement rooted at Document Element.
   * @return corresponding JSON String.
   * @throws JAXBException if an unpexted event happens during the conversion.
   */
  public String writeElementToJson (JAXBElement<T> rootElement) throws JAXBException {
    System.setProperty("javax.xml.bind.context.factory",
        "org.eclipse.persistence.jaxb.JAXBContextFactory");

    JAXBContext jaxbContext = JAXBContext.newInstance(classPath);
    Marshaller marshaller = jaxbContext.createMarshaller();
    marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
    marshaller.setProperty(JAXBContextProperties.MEDIA_TYPE, "application/json");
    marshaller.setProperty(JAXBContextProperties.JSON_INCLUDE_ROOT, false);
    StringWriter sw = new StringWriter();
    marshaller.marshal(rootElement, sw);
    return sw.toString();
  }

}
