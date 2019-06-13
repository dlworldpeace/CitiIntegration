package main.java;

public class BankFormatConverterException extends Exception {

  public BankFormatConverterException(Throwable cause) {
    super(cause);
  }

  public BankFormatConverterException(String message, Throwable cause) {
    super(message, cause);
  }

  public BankFormatConverterException(String message) {
    super(message);
  }

  public BankFormatConverterException() {
  }
}
