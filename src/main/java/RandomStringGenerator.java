package main.java;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;

public class RandomStringGenerator {

  /**
   * Generate a random string.
   *
   * return a secure random string of length preset
   */
  public String nextString() {
    for (int idx = 0; idx < buf.length; ++idx)
      buf[idx] = symbols[random.nextInt(symbols.length)];
    return new String(buf);
  }

  public static final String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  public static final String lower = upper.toLowerCase(Locale.ROOT);

  public static final String digits = "0123456789";

  public static final String alphanum = upper + lower + digits;

  private final Random random;

  private final char[] symbols;

  private final char[] buf;

  public RandomStringGenerator(int length, Random random, String symbols) {
    if (length < 1) throw new IllegalArgumentException();
    if (symbols.length() < 2) throw new IllegalArgumentException();
    this.random = Objects.requireNonNull(random);
    this.symbols = symbols.toCharArray();
    this.buf = new char[length];
  }

  /**
   * Create an alphanumeric string generator.
   */
  public RandomStringGenerator(int length, Random random) {
    this(length, random, alphanum);
  }

  /**
   * Create an alphanumeric strings from a secure generator.
   */
  public RandomStringGenerator(int length) throws NoSuchAlgorithmException {
    this(length, System.getProperty("os.name").toLowerCase().contains("win") ?
        SecureRandom.getInstance("Windows-PRNG") : new SecureRandom());
    // WIN Default constructor would have returned insecure SHA1PRNG algorithm
    // UNIX Default constructor would have returned secure NativePRNG algorithm
  }

  /**
   * Create session identifiers.
   */
  public RandomStringGenerator() throws NoSuchAlgorithmException {
    this(8);
  }

}
