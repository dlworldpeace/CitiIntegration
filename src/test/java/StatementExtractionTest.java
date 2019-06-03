//import java.io.ByteArrayInputStream;
//import java.io.IOException;
//import java.nio.charset.StandardCharsets;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.nio.file.Paths;
//import java.security.InvalidAlgorithmParameterException;
//import java.security.InvalidKeyException;
//import java.security.Key;
//import java.security.NoSuchAlgorithmException;
//import java.security.spec.InvalidKeySpecException;
//import javax.crypto.BadPaddingException;
//import javax.crypto.Cipher;
//import javax.crypto.IllegalBlockSizeException;
//import javax.crypto.NoSuchPaddingException;
//import javax.crypto.SecretKeyFactory;
//import javax.crypto.spec.DESedeKeySpec;
//import javax.crypto.spec.IvParameterSpec;
//import javax.mail.BodyPart;
//import javax.mail.MessagingException;
//import javax.mail.internet.MimeMultipart;
//import javax.mail.util.ByteArrayDataSource;
//import javax.mail.util.SharedByteArrayInputStream;
//import org.apache.commons.codec.binary.Base64;
//import org.apache.commons.io.IOUtils;
//
//public class StatementExtractionTest {
//
//  private static final String MIMEResponse =
//      "--MIMEBoundary_507394b48240916cb3902ce1b7c7ed985b66f7bb41781730\n"
//          + "Content-Type: text/xml; charset=UTF-8\n"
//          + "Content-Transfer-Encoding: binary\n"
//          + "Content-ID: <0.407394b48240916cb3902ce1b7c7ed985b66f7bb41781730@apache.org>\n"
//          + "\n"
//          + "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
//          + "<xenc:EncryptedData Type=\"http://www.w3.org/2001/04/xmlenc#Element\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#tripledes-cbc\"/><dsig:KeyInfo xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedKey Recipient=\"name:4935e330-b95e-4265-844a-0f21197bf799\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><dsig:KeyInfo><dsig:KeyName>4935e330-b95e-4265-844a-0f21197bf799</dsig:KeyName></dsig:KeyInfo><xenc:CipherData><xenc:CipherValue>o2rNvSDATROsmbRmKFCStg+VFf08h2d4Q0Ui4gmieRZ0ZsiY7vEcBj+PCguNuLd8jleZx+rxyYaEhu7h2Ia2ngERqplkuTfUDC2HFtW4mdI8FywseT8Q8p6JhvpQLMRfRMF3+c6vnQDT5W845+6bas6GDfiF/RGYOw4qU6xwnzHMayYyj3nQHsFnawUbTCUYJamHLT78hpxptMyCpQcpykCsrmaTiGM4ezWbBxsz2V/fqbzRZJHJBUpFzG2l3crtj1LeBnzMMQcN3K11QIhwX/xZzFXLdwf5YjoKB+43XlbHKKwv8CZwZ3mY9ahkWFH8aXL6DlIrNLiMfDg32puxFQ==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></dsig:KeyInfo><xenc:CipherData><xenc:CipherValue>q++hALKnCaQf0mErpmyOad5zIjSv7diA8US1wdl1tTHwdPU/VFtWyj6vxLZdGZhLfZDQ9mKAnpDiZexLQgN2BsU95193Z/fwL8JoOqXuhMSQOZjf7rNcWFRsjMZwIRGqhlzU0iofVxTYty+u8RXCDm6OqqypKtYZPVQzFQNw3E5vNQ/P1xyEbPsPqMF4weSGPFXMzILH9++Ll6K2d7TUcAECyYiPx+XWWXPa5sQ8GtMtET8AMpNj0cEdbP11OJKhsAIyPbDcNq56RBTBxogH2qNDC9JrvsS+2DOdB8n1iH4+DMSnIO1kQqFVDyQKkoaCuaOOsBr7Th3nJ/i0YHqjBqHSwduM/bC/oXDACvamb4Vub/UxvgtjVdcZy5IRqZtjq0y1l6Fovgxq7PAIp32k0gTRVCDse5LIkvl9gKnvHHWqqumlP9Tia3y9195E/6nbRRO2E+1tlOtrTlZ+8dZM53wLt8VIQDw/34JiMVYsUn8QFwjutFXzjS0bqF8QNCGdt7y7kbr2zqtFrqRpNF2W3MK+nehm/zRkcHRpuZhwPTPcQgLY6q6sUn7cF5AmXAx5F5Ef6sOTxbanZbuSmJ0hDDa2G3CeZufRXB0fUUAEjjMh2sBW8a2dQFr+8X+t7M0wPGmOoIbQ3uOEK5eaSMbGyjB3AP06JAMwH9BhbslNCYzBhKpZnqcAaZ04h33/mruqCXp7yWm5dCjskjglmT7RnMl6dkbJA2GHKd8BA4meaNzII8T04zymyeAyWf2gOI3SwsHDfoN+s3JMILlnJsNQFxnMhuJIS5tOK3iwPhpNUhYm4CMVAHbz1hxchqF0ct8YqrosbmsAMuxVVKFY/k5FvZOgnz8m8gndGKaPy41iVAZigvoMFnLElXcd7ti/WaHAT7Ni4jpWjDKaVSRj1gnFGEXeGQUtURA5ZqvNHBdf9mXMCB0HpAWjMvt27bbUTl6dk+1Xe3Lzycpx2Zo+OfkOODGnhS0uxPRDVXuPV5L0QkH5MMdWi5OJOPWm5SRs9nz9to+RfjnO2rdP3Ayg4ZgOzT/boUUv/vjfRDj32RxRIePIFtogWHQT1gO1Byb5OriDFAHp3HW192PitL21cwbxg9e4o4KRmSve+EBaiLA+JrgYq1cRE5jL3nvP9WyK1gOlKohvwxkl1cx82RmksvLrVIhY6oT3CsgBZ+xi6/fFF33R9kXKfhYsAIrJXHlFZbAi8G+gd7Tf6rhhLQzVLTQgGYE7jTPNljWPavHXmua9kZ3xxM+6AKwkLTKh2nPa+jZrpOO3UyHGsKH7/dXppN16REitsZ2NsT01aNzpyYzsFp5mZA/J0hnP5JzOsaxbHbRdeYOnHlU/SN40WLk5CvP0V/wNj39gVma1PgcjVHgQzQzPHYYOseCgRKBdpCGl+kl3WMvr9iVaz2ljj52AalSseAQ6ipz6i3FhPtCNn8AxtJI0gbiGtIgYMZfsw86/4MK+dUpCZgvlsq7pDmKHM8/ypkF//oyOpNpL6b+ilgqKeIdIzIXrtFp9l204RDFaqJKHZwZkXm9eSGGs4G17IlAYs8K0aYo7+VZulRwAURo2LV/iC+CxEN0lnS3cb1n7by0wg5kuMyKkf/tLD/9Huxs3Ilmh6fFT3eyW14rL7+M3reTPxrARshEVggQ5gPcNW7mBe8r0Agv+5vSFMAEZrpFzxW1bimjjE8b65I+goQxfi1HHxxCh5ZUpzcvFleYxxQBJUeJjMjCVhC8cAuj4iaxL5SKYaBafM1m3SprPm8OPQAVwlqfd+/JxQF9+Lbq3e1KUF98qZx7RLGWf7qRwRnfVY0LpUqYpbj4qNr++wL60ZI8NBGPJuvhDWgSEKoEeiWC4Eo+xPn9ubEvNLG9fXuMQxbc3znvENq7XKqlvzlXDsdchZVO9BGI4zy9JK1d7b7tGIarRASzQM99EZcoSPIpI2Px2dssPxtujiRRjGu36pRTfto9j762L02cQ8+exz3N/ops87FwWGc1nrl9s4+J6YgQi5LWFA0Wcofi7GMrQB9vm2M32TfYYciAida0n6q3Sd8UFEARuv7m2szXqVSRtrIxhr+zec4xswb/7RG6XfvzOgcvC6duqmA9tA+fYpx3U9p1a+TNhlxqQcrT22KuEQWGA7yTSOTGXPtTiuoS25BiTAmQI5jIoV7VDy5Qqw9ohuIvDdjvFDhel131A1G9weBAUYu1Aecho120ut1odFRZ3+fi9T1RL/uxfj/SWrk4E89oHy36iDUhswnP0z8SshbSsx1f4IhDIc8yxJngKOTFKZz0xpXwJm2pitKtpUmPm/7eOH24b+J37QsKe2BVmmIxcA4M2E1Hzgc10yW6GkyadrMYwztSEOtcp5veMyndBBcDevnUWKCtDztiEPZS4vTL3DJc0kud6aY4e5pbtlZcr8dUCl/DyacVietLaBaQ4Lu4eJUNhPezKdN++0vrLA1u/2HVzn6Ptrunc97khWujwyA4Tx8ueZRyZhyfORykRFJFlz28QafFMZFiumAfb5V38yt36R+VLPrxA7gaE4v1swE7bnMmhMnL6dG2Ga2M7T8tttgWVCqRfJx+X8ED3eNC/QIbUOBz9I5OPnJ+qp39LsDFbKOnB8yOOQmIwQzfkShBLdooZ0Ho8pmHUv7WGedH9fB+KJXomsR+BWa0WntBo/zgRWfFS0CfuWbajpPvagtYMN5vX1DEJxUpq5XBjsrNqOWwCiPBPhtY0HgIfzh303T1iL2FDIDlfeAdQ74uR1fgV4ramS/gidG9JE4BJK5mYucSll0/ZXGJCbStnJRYtxaH4DrpDCfI+8cXL1Pw8JsDyiYlBMjz2szoOWTNUfBVcGcw9k2BKUuhch+N+922YCgma4bOB9TVfV6UH3eYpgJNuxsDNZH86yM/c6BSZxPxejmqvBGmAFl4hRsYBdvmd8TIi4F7yOrLfGSFNc40IzzqROsB3tvj79++qOt2Qe/cOSj/YSVeCFZ/BKMo571W85ciyAFxDkJbecVrS6oHq8fZZSdMuVGQ/eXwF4sd+KflInQths59hjn+qNfhhYAB5mvc0I0oZWd9j7f75k3BX7wZjZU/Ywnf21hOesjvMtgzlwk+LtFo/iSx6LcTDGnzxh4VxlOx0uKwhXb7vj4LzgrM9bK6fTzUozTw6gEez8TKODwIWrgf6zPBxVdA3MUDWfuzaYk31A4BL8Wj94+eKr3unk2wwh9PNEkhpWqN///f2tesI2I8dGZ/hwqhDkegF0RW8nnnAGfUtTxxgLIK0jn4h2D1DT9OQ2s6sUu030nOsldlx+B4zxtcMU/XGe7jGs0pH4YKluVb5RLAQuOuxIlVJMXwX7RffCkVuMhcF0w6YWwhTtBxASdee5zz756K2ooiaajEG9BRGOrwijPhNScaQBKMCIosBeoVKIFwSpHowAp6A9t3WoEh9FMGyif997veu3so31pXukmQVZ0bjnqtfDFAjBXoHlS8lvpIRcSI51rPRZsjj7P/l0Pvd+9Tu3T39u7i0VuOUSpL0QemffqiTDH8HbKS8h5TZeqvg/rOUfpwKpAIR/yPJxO8mJhoX1a4wblbfoVQPHvklunoS9bvaXOW/1pgQZ9x/cF3T5/ClPONko8HfxB4QSJofOhxM9VeOOA2K/MHr7gQ7c5TdjsKvVN5T95xb5u5hIpwl7sTxcNldsPZilLaZq+xp6K0hZZWFtOclxvYBNqAQOZWTPzDsiy2rFMxu+FCnW/Q4niOCEYWUMe8IaYB7SIoLdTroyZ1Os/s6Iy2SMos115Hb9rY8frYCxOUZCYfisjq3l3gl6t/nbFu4Pp8FXuf6vnRPCcdb+7jxPyoe4apnf7UeL4ry2PNVmSfNtXFL5YTS/o0NLacUCUErZuV83iPLC7OnvfLY2u48hJBML5pwUBByz8BZomdsRJ/GH//M+pNeuqnjjxAVkgPZjIMoo7hrPErcaXVoOD/fJlI8hylG2a1nChHOKJ4MYIxgrlH6oBl/vcD/HHc0xfEuqFuvbK3FH+fk3E7nJoV6XwXWoLts/pL5jCS/dxKtc7NLSQM6PIhh5pRrPx3dsUqosGa90RGExI4HavQrm7AdM4r+RGVA/Zk2XNJ/muhXXnjteiuQKqv5O9q31MYAVGcjyflNRJ2QhRtYXFY6gSv5wph6yKNySewrnmk3wLDzodeJWEOkIwh8W94qLEecZBjWjg9VqCrP1W5atUN3LoNUqZ/rEK3VlM1WABBAnrecuyP5YDpg1cpa5ZXsyb3SHBefr0Fx8Bnt8f5SfAq/W1lkg/ILDrnP8A//jMSzHGzC1rj1MRlCdlOuIPpDPlSkSN+133xXbF+p5IynzcT2uXc6bU7oSHtT6N3rKq1e6b08XW+AFlUmz1cEKNbvrgqkf0EaNSyR2iOrdZr+ZwMDPP0hCJfbCiLDJ3CqRJu6e23l6PJePn18jFZL8djSB+ELpLXwvlDzl9e/TNcBFfqgp8Hbr2yjuBBAb9zmnVipqEhkPLQnfNbS6jWS0SZpWJ9Fvd0WZUUO4AbuPbNU9URNCIKZjjgHr9xoKFwox3QVsgSlgOR1kTjfru1448gmjfPdlZ8D0h3sPgMROjlj3DVYNjfb6ZLhPsg8CTDJQMXccYm9UhnCcqdf1kC2eR+ECutMgWt4LasnPeMpwwuZp/21KoCrjRh69Hojht2ocmxPu+ZeuaKZNLeSOCGlw0XqKatZnj/mGkxc76IsbsWzeW+jwjIolge53oTZw2nhbvSiV4EgihEAfhb5Bac3rWu8SSWDCUUKKrmdkbLD3LDps0c8tITgDdtfipNgGFtp0IUOrmCmlR4z/5IZWUFMn7YE/p7218rq5HLbRZXr8x9ERTlmEDxAIPdwTQWjhqYpqw3+ZrBfgpmTI1yDhcyNojtVLFp1tbgEVaEDQe99ZmXRgOX2cNyLC8yT+V/fkzCwQxS4g9cAauF+D29m/CZtZOGBnLmEIjj37QTycAWAGUUB/aSl4Xt6HwrWINf0AyWUNW0h5R7O3A8t2K/0SQNwj+kdeTxaoo+3Yrju8v4bIvWHZmpCjjkKLqG56SmVNCTXWwKsFazWs8L4PdF2MM8rqHPQ+x3CGM1ASi7KMf5bMmqlPPcLEofoU0jybYLfPhGcTx/yRoP9inMtOcAi0GX2UDHvqFTLAxT03gZNHetdZ0oJi0oPmTo88tFUUQU+ttlltr5WtCl0XSVMI/m0k7jJHXIkk7Z1pJUDEPpDCIgiFsWqclyJWo8oL8MYGgVGTBS/DpV/8lFy9a62W6dN/SZJCmAMfIlYVI5Xwka7Ty3A4U+zZCVjpIz3ZyN351MSK1vjT2PWzggB87RqF3RBKl6NdJ1DiFqIvPWKMvKZBoX8ZDqdwJa1UASIxXfdEAIx8FE8vAeqyjD+e6TyUh6UyPoyxX8j40XcvFkz0RlG9RU2v1mpwd1GZg20i5jNsS4P4Zl3At2BKyoKN6j6Abkk03tOfwq7KzD+HVCShG3cVGQv7rL7Lr54gMg5bbIz0gG71+Xv4t5Uw+InHO/omDUUP8Vxb/OvWNrFAGP+CaVwZDrwzN00yiQtvb/tXVMF6PBrgluqKCZoBLHibfLC7VbEqhdTJ05u2EU4nA0ze+I9nt+tWDJEnEhETaKm6lI8+0Ax4mTv2rkG+K7t45+jas8wHexrvnn7yQpUvS4vgnIttRo1olMW6QObxc0Sii1Rv9X0/mn1CJrZZT0Zqp+e7r944xcGVOc7RCm6qebPm8X0hh0Rct1BMJKYeFuPjngZMlfBJUiGKxSvybsDdrFPwDsKApvLkd+YKU+4FOc7D5uzmUoxNJKJ4OgbvB50or4lTXOvPbbJpbpaPAmraxwF3xUymfYG+n8omP1dBW+2K+OugO0G7ZdusKJdTosmWXoFCewxr+eusGI+HBTOzxusUnjj7/GoEbGJbmhfx/9Dp7urd1n3qvjkdEVeON06aCfAFFtPSHPm9gnqedloDZhCghzTuXrjqgCT3hoJry/0X1GwwpNTDBtLOz/OpaWulhaxq6lcitDct42rRH87HXjjjMepjL0+SKLZMWR+RH5vwFrrfSSfgIaG9wnh3Io/nmgf5JO8hiIfcO4sWoC7J6wkuVWlFXEw3Qu+GMV5OWdfQwMD4//BZvpRqp8h7q3jXnTxW4gTxj2n4dUGqiJczGLONniTT8fffzLJttgVAD4CPFj/EnNkwPBJd8HQCwoJLT76nPN+lNd/QhM5HnSgYYS6U6DisLxgdtdwdalYnbdPDV5N2EhCAvy+g6wyf2Lbhd+AYBJaJ29y416nZvAAj+MSVwryvwlIwA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>\n"
//          + "--MIMEBoundary_507394b48240916cb3902ce1b7c7ed985b66f7bb41781730\n"
//          + "Content-Type: application/octet-stream\n"
//          + "Content-Transfer-Encoding: binary\n"
//          + "Content-ID: <207394b48240916cb3902ce1b7c7ed985b66f7bb41781730@apache.org>\n"
//          + "\n"
//          + "絊^\uE589\uE2C6?i,暅\fAAF-3孞\u001E?枽鮨?:#?\u0004\u007F\u0013?iLj\u007F?>?\u000E\u0010?\u001F嚤?A隷u?\u0019??Ｄ\t\fuq葽烩唎\"l\u001B??\"S?\uF8F5_醳l啞Z[鰈s?罘靖B\u001E╂?⒄??{~絻\u0012辷??c梼?W蝵I橣3\uE4EA*s搖鍯\uE7D0吴徵\u0013#\uE183棚戩\u000EYd\u0001颵K澹gd喹\uE363I\u0012S3磳壝^hKil\u00148驣b薪<3€\u0013蚏呴?舷'?鲁\u0006\u0002??\u001A=X\u001EW隟衠刅\u001F恚T(\\猒0?\u001B\u0004甍摕?9?p芔瀯.";
//
//  private static String parseMIMEResponse(byte[] response, Path path)
//      throws HandlerException{
//    try {
//      String responseStatRetXMLStr = "";
//      MimeMultipart mp = new MimeMultipart(new ByteArrayDataSource(response,
//          org.springframework.http.MediaType.TEXT_XML_VALUE));
//      for (int i = 0; i < mp.getCount(); i++) {
//        BodyPart bodyPart = mp.getBodyPart(i);
//
//        if (bodyPart.isMimeType("text/xml") ||
//            bodyPart.isMimeType("application/xml")) {// if text/xml
//          if (SharedByteArrayInputStream.class
//              .equals(bodyPart.getContent().getClass())) {
//            responseStatRetXMLStr = IOUtils.toString((SharedByteArrayInputStream)
//                bodyPart.getContent(), StandardCharsets.UTF_8);
//          } else {
//            responseStatRetXMLStr = (String) bodyPart.getContent();
//          }
//        } else { //if application/octet-stream or application/xop+xml
//          if (String.class.equals(bodyPart.getContent().getClass())) {
//            Files.write(path, ((String) bodyPart.getContent()).getBytes());
//          } else {
//            ByteArrayInputStream bais =
//                (ByteArrayInputStream) bodyPart.getContent();
//            Files.copy(bais, path);
//          }
//        }
//      }
//      return responseStatRetXMLStr;
//    } catch (MessagingException | IOException e) {
//      throw new HandlerException(e.getMessage());
//    }
//  }
//
//  /**
//   * Decrypt the encrypted attachment (excluding its first 8 bytes) using the
//   * decryption key and IvParameterSpec instance from the xml section of MIME
//   * response.
//   *
//   * @param decryptionKey the decryption key.
//   * @param input encrypted attachment (including first 8 bytes).
//   * @return decrypted statement file.
//   * @throws HandlerException custom exception for Handler class.
//   */
//  private byte[] des3DecodeCBC(String decryptionKey, byte[] input)
//      throws HandlerException {
//    try {
//      // attachment byte array from MIME response
//      int ivLen = 8;
//      byte[] keyiv = new byte[ivLen];
//      System.arraycopy(input, 0, keyiv, 0, ivLen);
//
//      int dataLen = input.length - ivLen;
//      byte[] data = new byte[dataLen];
//      System.arraycopy(input, ivLen, data, 0, dataLen);
//
//      DESedeKeySpec spec = new DESedeKeySpec(
//          Base64.decodeBase64(decryptionKey));
//      SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
//      Key desKey = keyFactory.generateSecret(spec);
//
//      Cipher cipher = Cipher.getInstance("TripleDES/CBC/NoPadding");
//      IvParameterSpec ips = new IvParameterSpec(keyiv);
//      cipher.init(Cipher.DECRYPT_MODE, desKey, ips);
//
//      byte[] bout = cipher.doFinal(data);
//
//      return Base64.decodeBase64(bout);
//    } catch (InvalidKeyException | NoSuchAlgorithmException | BadPaddingException |
//        InvalidKeySpecException | NoSuchPaddingException | IllegalBlockSizeException
//        | InvalidAlgorithmParameterException e) {
//      throw new HandlerException(e.getMessage());
//    }
//  }
//
//  public static void main (String[] args) {
//    try {
//      // TODO: change this path to relative path for your own testing!
//      Path outputPath = Paths.get("C:\\Users\\dlwor\\Desktop\\deskera\\test\\src\\output.txt");
//      String xmlSection = parseMIMEResponse(MIMEResponse.getBytes(), outputPath);
//      System.out.println(xmlSection);
//    } catch (Exception e) {
//      e.printStackTrace();
//    }
//
//  }
//}