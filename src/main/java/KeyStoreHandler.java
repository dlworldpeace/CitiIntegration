package main.java;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryNotEmptyException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.nio.file.Paths;
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
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * This class covers all operation with loading certificate and private key into
 * a PKCS12 format keystore file.
 *
 * @author Sagar Mahamuni and Xiao Delong.
 * @version 1.0
 * @since 2019-06-17.
 */
public class KeyStoreHandler {

  private static final byte[] HEADER = "-----".getBytes(StandardCharsets.US_ASCII);

  /**
   * Create a .p12 keystore file in the file system from a compatibble pair of
   * public cert and a private key
   *
   * @param certificate Path to .crt file from input
   * @param key Path to .key file from input
   * @param keystore Path to the new .p12 keystore generated for output
   * @param password char array of password to protect the keystore generated
   * @throws KeyStoreHandlerException if an unexpected event occurs when loading
   *                                  input files from or writing new file into
   *                                  the file system, or if an unexpected event
   *                                  occurs during keys operations
   */
  public static void createKeystoreFromCertAndKey(String certificate, String key,
      String keystore, char[] password) throws KeyStoreHandlerException {
    try {
      byte[] pkcs8 = decode(Files.readAllBytes(Paths.get(key)));
      KeyFactory kf = KeyFactory.getInstance("RSA");
      PrivateKey pvt = kf.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      Certificate pub;
      try (InputStream is = Files.newInputStream(Paths.get(certificate))) {
        pub = cf.generateCertificate(is);
      }
      KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
      pkcs12.load(null, null);
      pkcs12.setKeyEntry("identity", pvt, password, new Certificate[]{pub});
      try (OutputStream s = Files
          .newOutputStream(Paths.get(keystore), StandardOpenOption.CREATE_NEW)) {
        pkcs12.store(s, password);
      }
    } catch (IOException | GeneralSecurityException e) {
      Logger.getLogger(Handler.class.getName()).log(Level.SEVERE, null, e);
      throw new KeyStoreHandlerException(e.getMessage());
    }
  }

  /**
   * Decode a base64 encoded private key
   *
   * @param raw byte array of raw key data
   * @return decoded information of the encoded key string
   */
  private static byte[] decode(byte[] raw) {
    if (!Arrays.equals(Arrays.copyOfRange(raw, 0, HEADER.length), HEADER))
      return raw;
    CharBuffer pem = StandardCharsets.US_ASCII.decode(ByteBuffer.wrap(raw));
    String[] lines = Pattern.compile("\\R").split(pem);
    String[] body = Arrays.copyOfRange(lines, 1, lines.length - 1);
    return Base64.getDecoder().decode(String.join("", body));
  }

  /**
   * Delete a .p12 extension key store file if it exists in the path specified
   *
   * @param p12KeyStore Path to a specific .p12 keystore file
   * @throws KeyStoreHandlerException if the file path specified does not end
   *                                  with .p12
   */
  public static void deleteP12IfExists (String p12KeyStore)
      throws KeyStoreHandlerException {
    try {
      PathMatcher matcher = FileSystems.getDefault()
          .getPathMatcher("glob:**/*.p12");
      if (!matcher.matches(Paths.get(p12KeyStore)))
        throw new KeyStoreHandlerException("File path specified does not end with .p12");

      boolean isDeleted = Files.deleteIfExists(Paths.get(p12KeyStore));
      if (isDeleted)
        Logger.getLogger(Handler.class.getName())
            .log(Level.INFO, "Delete specified .p12 successful");
      else
        Logger.getLogger(Handler.class.getName())
            .log(Level.INFO, "No such file/directory exists");
    } catch(IOException e) {
      Logger.getLogger(Handler.class.getName())
          .log(Level.SEVERE, "Invalid permissions");
      throw new KeyStoreHandlerException("Invalid permissions");
    }
  }

}
