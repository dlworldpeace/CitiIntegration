package main.java;

public class HandlerException extends Exception {

  public HandlerException(Throwable cause) {
    super(cause);
  }

  public HandlerException(String message, Throwable cause) {
    super(message, cause);
  }

  public HandlerException(String message) {
    super(message);
  }

  public HandlerException() {
  }
}
