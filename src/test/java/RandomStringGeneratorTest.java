package test.java;

import java.security.SecureRandom;
import junit.framework.TestCase;
import main.java.RandomStringGenerator;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class RandomStringGeneratorTest extends TestCase {

  @Test
  public void nextString_success () {
    RandomStringGenerator rsg = new RandomStringGenerator();
    System.out.println(rsg.nextString());
  }

  @Test (expected = IllegalArgumentException.class)
  public void RandomStringGenerator_lengthZero_throwsException () {
    RandomStringGenerator rsg = new RandomStringGenerator(0);
  }

  @Test
  public void RandomStringGenerator_lengthOne_initiateSuccess () {
    RandomStringGenerator rsg = new RandomStringGenerator(1);
  }

  @Test (expected = NullPointerException.class)
  public void RandomStringGenerator_nullRandomInstance_throwsException () {
    RandomStringGenerator rsg = new RandomStringGenerator(1, null);
  }

  @Test (expected = IllegalArgumentException.class)
  public void RandomStringGenerator_oneSymbol_throwsException () {
    RandomStringGenerator rsg =
        new RandomStringGenerator(1, new SecureRandom(), "a");
  }

  @Test
  public void RandomStringGenerator_twoSymbol_initiateSuccess () {
    RandomStringGenerator rsg =
        new RandomStringGenerator(1, new SecureRandom(), "aa");
  }

}