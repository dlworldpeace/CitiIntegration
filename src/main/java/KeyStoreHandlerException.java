package main.java;

public class KeyStoreHandlerException extends Exception {

  public KeyStoreHandlerException(Throwable cause) {
    super(cause);
  }

  public KeyStoreHandlerException(String message, Throwable cause) {
    super(message, cause);
  }

  public KeyStoreHandlerException(String message) {
    super(message);
  }

  public KeyStoreHandlerException() {
  }
}