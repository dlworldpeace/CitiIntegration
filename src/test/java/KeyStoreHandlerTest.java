package test.java;

import static main.java.KeyStoreHandler.createKeystoreFromCertAndKey;
import static main.java.KeyStoreHandler.deleteP12IfExists;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;
import junit.framework.TestCase;
import main.java.KeyStoreHandlerException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class KeyStoreHandlerTest extends TestCase {

  private final String CERT_PATH =
      "src/main/resources/key/deskera/deskera_sign_encryption_pubkey.crt";
  private final String KEY_PATH =
      "src/main/resources/key/deskera/deskera_customer_private.key";
  private final String KS_PATH = "src/test/resources/key/as9Jijl4P2Yjhs.p12";
  private final String NONEXSISTENT_KS_PATH = "src/test/resources/key/ha2dTaNfpOn.p12";
  private final String FOLDER_PATH = "src/test/resources/key/";
  private final String KS_PASSWORD = "7NLuioh2zn80";

  @Test
  public void createKeystoreFromCertAndKey_deskeraCrtAndPrivKey_success ()
      throws KeyStoreHandlerException {

    deleteP12IfExists(KS_PATH);
    createKeystoreFromCertAndKey(
        CERT_PATH, KEY_PATH, KS_PATH, KS_PASSWORD.toCharArray());
  }

  @Test
  public void deleteP12IfExists_existingP12_deletionSuccess ()
      throws KeyStoreHandlerException {

    deleteP12IfExists(KS_PATH);
    File f = new File(KS_PATH);
    createKeystoreFromCertAndKey(
        CERT_PATH, KEY_PATH, KS_PATH, KS_PASSWORD.toCharArray());
    assertTrue(f.exists() && !f.isDirectory());
    deleteP12IfExists(KS_PATH);
    assertFalse(f.exists() && !f.isDirectory());
  }

  @Test
  public void deleteP12IfExists_nonExistentP12_noDeletion ()
      throws KeyStoreHandlerException {
    deleteP12IfExists(NONEXSISTENT_KS_PATH);
  }

  @Test (expected = KeyStoreHandlerException.class)
  public void deleteP12IfExists_nonFile_throwsException ()
      throws KeyStoreHandlerException {
    deleteP12IfExists(FOLDER_PATH);
  }
}