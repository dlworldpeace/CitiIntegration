package test.java;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import junit.framework.TestCase;
import main.java.RandomStringGenerator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class RandomStringGeneratorTest extends TestCase {

  @Test
  public void nextString_success() throws NoSuchAlgorithmException {
    RandomStringGenerator rsg = new RandomStringGenerator();
    System.out.println(rsg.nextString());
  }

  @Test (expected = IllegalArgumentException.class)
  public void randomStringGenerator_lengthZero_throwsException()
      throws NoSuchAlgorithmException {
    RandomStringGenerator rsg = new RandomStringGenerator(0);
  }

  @Test
  public void randomStringGenerator_lengthOne_initiateSuccess()
      throws NoSuchAlgorithmException {
    RandomStringGenerator rsg = new RandomStringGenerator(1);
  }

  @Test (expected = NullPointerException.class)
  public void randomStringGenerator_nullRandomInstance_throwsException() {
    RandomStringGenerator rsg = new RandomStringGenerator(1, null);
  }

  @Test (expected = IllegalArgumentException.class)
  public void randomStringGenerator_oneSymbol_throwsException() {
    RandomStringGenerator rsg =
        new RandomStringGenerator(1, new SecureRandom(), "a");
  }

  @Test
  public void randomStringGenerator_twoSymbol_initiateSuccess() {
    RandomStringGenerator rsg =
        new RandomStringGenerator(1, new SecureRandom(), "aa");
  }

}