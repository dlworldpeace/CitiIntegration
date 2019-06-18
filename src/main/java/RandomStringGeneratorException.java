package main.java;

public class RandomStringGeneratorException extends Exception {

  public RandomStringGeneratorException(Throwable cause) {
    super(cause);
  }

  public RandomStringGeneratorException(String message, Throwable cause) {
    super(message, cause);
  }

  public RandomStringGeneratorException(String message) {
    super(message);
  }

  public RandomStringGeneratorException() {
  }
}