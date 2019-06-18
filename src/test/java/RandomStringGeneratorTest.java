package test.java;

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

}