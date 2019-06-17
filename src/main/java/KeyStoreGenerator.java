package main.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * This class covers all operation with loading certificate and private key into
 * a PKCS12 format keystore file.
 *
 * @author Sagar Mahamuni and Xiao Delong.
 * @version 1.0
 * @since 2019-06-17.
 */
public class KeyStoreGenerator {

  private static final byte[] HEADER = "-----".getBytes(StandardCharsets.US_ASCII);

  public static void createIdentityStore(Path certificate, Path key, Path keystore,
      char[] password) throws IOException, GeneralSecurityException {
    byte[] pkcs8 = decode(Files.readAllBytes(key));
    KeyFactory kf = KeyFactory.getInstance("RSA");
    PrivateKey pvt = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    Certificate pub;
    try (InputStream is = Files.newInputStream(certificate)) {
      pub = cf.generateCertificate(is);
    }
    KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
    pkcs12.load(null, null);
    pkcs12.setKeyEntry("identity", pvt, password, new Certificate[] { pub });
    try (OutputStream s = Files.newOutputStream(keystore, StandardOpenOption.CREATE_NEW)) {
      pkcs12.store(s, password);
    }
  }

  private static byte[] decode(byte[] raw) {
    if (!Arrays.equals(Arrays.copyOfRange(raw, 0, HEADER.length), HEADER)) return raw;
    CharBuffer pem = StandardCharsets.US_ASCII.decode(ByteBuffer.wrap(raw));
    String[] lines = Pattern.compile("\\R").split(pem);
    String[] body = Arrays.copyOfRange(lines, 1, lines.length - 1);
    return Base64.getDecoder().decode(String.join("", body));
  }
}
