package test.java;

import static main.java.KeyStoreGenerator.createKeystoreFromCertAndKey;

import java.io.IOException;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import junit.framework.TestCase;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class KeyStoreGeneratorTest extends TestCase {

  @Test
  public void createKeystoreFromCertAndKey_deskeraCrtAndPrivKey_success ()
      throws IOException, GeneralSecurityException {

    createKeystoreFromCertAndKey(
        Paths.get("src/main/resources/key/deskera/deskera_sign_encryption_pubkey.crt"),
        Paths.get("src/main/resources/key/deskera/deskera_customer_private.key"),
        Paths.get("src/test/resources/key/new.p12"),
        "123123123".toCharArray()
    );
  }
}