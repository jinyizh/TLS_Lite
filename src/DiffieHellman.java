import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

/**
 * This helper class contains variables and methods that are necessary in the Diffie-Hellman key exchange process.
 * It only contains methods that are used by both ends and that are related to the Diffie-Hellman key exchange process.
 */
public class DiffieHellman {
  // Used as g in DHKE, same for both server and client
  public static BigInteger g = new BigInteger("5");

  // Used as n in DHKE, same for both server and client
  // https://www.ietf.org/rfc/rfc3526.txt - 3. 2048-bit MODP Group
  public static String MODPString = (
      "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1 " +
          "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD " +
          "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245 " +
          "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED " +
          "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D " +
          "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F " +
          "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D " +
          "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B " +
          "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9 " +
          "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510 " +
          "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF"
  ).replaceAll("\\s", ""); // remove all whitespaces

  public static byte[] serverPublicKey;
  public static byte[] signedServerPublicKey;
  public static byte[] clientPublicKey;
  public static byte[] signedClientPublicKey;

  /**
   * Generates a secret 2048-bit number k used for public key generation
   *
   * @return the random number k generated
   */
  public static BigInteger generatePrivateKey() {
    Random random = new Random();
    return new BigInteger(2048, random);
  }

  /**
   * Used by server and client to compute the Diffie-Hellman public key
   *
   * @param g public base
   * @param k private key (ks or kc)
   * @param n public modulus
   * @return public key computed
   */
  public static BigInteger generatePublicKey(BigInteger g, BigInteger k, BigInteger n) {
    return g.modPow(k, n);
  }

  /**
   * USed by server and client to sign the Diffie-Hellman public with an RSA private key
   *
   * @param publicKey  Diffie-Hellman public to be signed
   * @param privateKey RSA private key generated to sign the DH public key
   * @return signed DH public key
   * @throws NoSuchAlgorithmException NoSuchAlgorithmException
   * @throws SignatureException       SignatureException
   * @throws InvalidKeyException      InvalidKeyException
   */
  public static byte[] signPublicKey(byte[] publicKey, PrivateKey privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    Signature signature = Signature.getInstance("SHA256WithRSA");
    signature.initSign(privateKey, new SecureRandom());
    signature.update(publicKey);
    return signature.sign();
  }

  /**
   * Used for both server and client to verify signed Diffie-Hellman public key from the other end
   *
   * @param socket   socket of the other end
   * @param messages all handshake messages for sending MAC, passed from each class's member variable
   * @return all handshake messages for sending MAC, passed from each class's member variable
   * @throws IOException              IOException
   * @throws NoSuchAlgorithmException NoSuchAlgorithmException
   * @throws InvalidKeyException      InvalidKeyException
   * @throws SignatureException       SignatureException
   * @throws CertificateException     CertificateException
   * @throws NoSuchProviderException  CertificateException
   */
  public static byte[] verifyPublicKey(Socket socket, ByteArrayOutputStream messages) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException {
    // Inside the TLS handshake the RSA key is used in the given ciphers for authentication.
    // This is done by the server signing some data with the private key, where
    // the data at least partially depend on the client.
    // The client then can validate this signature and thus verify that
    // the other party has access to the private key matching the public key of the certificate.

    // A private key can be used to decrypt a message that was encrypted using the corresponding public key, or to sign a message;
    // but a private key cannot be used to encrypt a message.

    // Receive information sent from the other end:
    // receive certificate from the client
    byte[] certificate = receiveBytes(socket);
    messages.writeBytes(certificate);
    PublicKey RSAPublicKey = getRSAPubKey(certificate);
    PublicKey CAPublicKey = getCAPublicKey();
    Certificate CACertificate = getCertificate(certificate);
    CACertificate.verify(CAPublicKey);
    System.out.println("verification of public key succeeded");
    // receive Diffie-Hellman public key from the client
    byte[] DHPublicKey = receiveBytes(socket);
    messages.writeBytes(DHPublicKey);
    // receive (signed) DH public key from the client
    byte[] signedDHPublicKey = receiveBytes(socket);
    messages.writeBytes(signedDHPublicKey);

    // actual verification, ref: https://jenkov.com/tutorials/java-cryptography/signature.html
    Signature signature = Signature.getInstance("SHA256WithRSA");
    signature.initVerify(RSAPublicKey);
    assert DHPublicKey != null;
    signature.update(DHPublicKey);
    if (!signature.verify(signedDHPublicKey)) {
      socket.close();
      System.exit(1);
    }
    return DHPublicKey;
  }

  /**
   * Generate shared secret key after authentication is established
   *
   * @param tBytes public key from the other end in byte array
   * @param k      private key
   * @param n      public modulus
   * @return computed shared secret key
   */
  public static BigInteger generateSharedSecret(byte[] tBytes, BigInteger k, BigInteger n) {
    BigInteger t = new BigInteger(tBytes);
    return t.modPow(k, n); // .toByteArray()
  }

  // the following 6 methods create secret key specs

  public static SecretKeySpec generateServerEncrypt(byte[] prk) throws NoSuchAlgorithmException, InvalidKeyException {
    return new SecretKeySpec(hkdfExpand(prk, "server encrypt"), "AES");
  }

  public static SecretKeySpec generateClientEncrypt(SecretKeySpec serverEncrypt) throws NoSuchAlgorithmException, InvalidKeyException {
    return new SecretKeySpec(hkdfExpand(serverEncrypt.getEncoded(), "client encrypt"), "AES");
  }

  public static SecretKeySpec generateServerMAC(SecretKeySpec clientEncrypt) throws NoSuchAlgorithmException, InvalidKeyException {
    return new SecretKeySpec(hkdfExpand(clientEncrypt.getEncoded(), "server MAC"), "AES");
  }

  public static SecretKeySpec generateClientMAC(SecretKeySpec serverMAC) throws NoSuchAlgorithmException, InvalidKeyException {
    return new SecretKeySpec(hkdfExpand(serverMAC.getEncoded(), "client MAC"), "AES");
  }

  public static IvParameterSpec generateServerIV(SecretKeySpec clientMAC) throws NoSuchAlgorithmException, InvalidKeyException {
    return new IvParameterSpec(hkdfExpand(clientMAC.getEncoded(), "server IV"));
  }

  public static IvParameterSpec generateClientIV(IvParameterSpec serverIV) throws NoSuchAlgorithmException, InvalidKeyException {
    return new IvParameterSpec(hkdfExpand(serverIV.getIV(), "client IV"));
  }

  /**
   * Hash-based message authentication code function
   *
   * @param key  SecretKeySpec
   * @param data byte array read from stream
   * @return hash in byte array
   * @throws NoSuchAlgorithmException NoSuchAlgorithmException
   * @throws InvalidKeyException      InvalidKeyException
   */
  public static byte[] HMAC(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
    Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
    SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
    sha256_HMAC.init(keySpec);
    return sha256_HMAC.doFinal(data);
  }

  /**
   * Used by the server and the client to send MAC to the other end
   *
   * @param socket socket
   * @param MACKey MAC key
   * @param baos   ByteArrayOutputStream
   * @throws InvalidKeyException      InvalidKeyException
   * @throws NoSuchAlgorithmException NoSuchAlgorithmException
   * @throws IOException              IOException
   */
  public static void sendMAC(Socket socket, SecretKeySpec MACKey, ByteArrayOutputStream baos) throws InvalidKeyException, NoSuchAlgorithmException, IOException {
    byte[] HMAC = HMAC(MACKey.getEncoded(), baos.toByteArray());
    sendBytes(socket, HMAC);
    baos.writeBytes(HMAC);
  }

  /**
   * Used by the server and the client to receive MAC from the other end
   *
   * @param socket socket
   * @param MACKey MAC key
   * @param baos   ByteArrayOutputStream
   * @throws IOException              IOException
   * @throws InvalidKeyException      InvalidKeyException
   * @throws NoSuchAlgorithmException NoSuchAlgorithmException
   */
  public static void receiveMAC(Socket socket, SecretKeySpec MACKey, ByteArrayOutputStream baos) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
    byte[] HMAC_received = receiveBytes(socket);
    byte[] HMAC = HMAC(MACKey.getEncoded(), baos.toByteArray());
    assert HMAC_received != null;
    for (int i = 0; i < HMAC_received.length; i++) {
      if (HMAC_received[i] != HMAC[i]) {
        System.out.println("error: received HMAC and HMAC are not the same");
        System.exit(1);
      }
    }
    baos.writeBytes(HMAC_received);
  }

  /**
   * Used by the server and the client to send messages to the other end after handshake is established
   *
   * @param socket  socket to which the encrypted message is sent
   * @param message message to be sent to the other end
   * @param key     key used to generate secret key spec
   * @param IV      IV for initializing encryption
   * @throws IOException                        IOException
   * @throws NoSuchPaddingException             NoSuchPaddingException
   * @throws InvalidAlgorithmParameterException InvalidAlgorithmParameterException
   * @throws NoSuchAlgorithmException           NoSuchAlgorithmException
   * @throws IllegalBlockSizeException          IllegalBlockSizeException
   * @throws BadPaddingException                BadPaddingException
   * @throws InvalidKeyException                InvalidKeyException
   */
  public static void sendMessage(Socket socket, String message, SecretKeySpec key, IvParameterSpec IV) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
    byte[] toBeSent = message.getBytes(StandardCharsets.UTF_8);
    int chunkSize = 100; // Divide the bytes
    int numOfChunks = (int) Math.ceil(toBeSent.length / (double) chunkSize);
    DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
    dos.writeInt(numOfChunks);
    for (int i = 0; i < numOfChunks; i++) {
      byte[] messageBytes = Arrays.copyOfRange(toBeSent, i * chunkSize, (i + 1) * chunkSize);
      byte[] HMAC = HMAC(key.getEncoded(), messageBytes);
      // concatenate massage and HMAC
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      baos.writeBytes(messageBytes);
      baos.writeBytes(HMAC);
      byte[] concatenatedBytes = baos.toByteArray();
      // encrypt and send
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, key, IV);
      sendBytes(socket, cipher.doFinal(concatenatedBytes));
    }
  }

  /**
   * Used by the server and the client to receive messages from the other end after handshake is established
   *
   * @param socket socket to which the encrypted message is sent
   * @param key    message to be sent to the other end
   * @param IV     IV for initializing encryption
   * @return message sent from the other end
   * @throws IOException                        IOException
   * @throws InvalidKeyException                InvalidKeyException
   * @throws NoSuchAlgorithmException           NoSuchAlgorithmException
   * @throws IllegalBlockSizeException          IllegalBlockSizeException
   * @throws BadPaddingException                BadPaddingException
   * @throws InvalidAlgorithmParameterException InvalidAlgorithmParameterException
   * @throws NoSuchPaddingException             NoSuchPaddingException
   */
  public static String receiveMessage(Socket socket, SecretKeySpec key, IvParameterSpec IV) throws IOException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataInputStream dis = new DataInputStream(socket.getInputStream());
    int numOfChunks = dis.readInt();
    for (int i = 0; i < numOfChunks; i++) {
      byte[] encrypted = receiveBytes(socket);
      // decrypt message
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.DECRYPT_MODE, key, IV);
      assert encrypted != null;
      byte[] original = cipher.doFinal(encrypted);
      // write message to output stream
      byte[] message = new byte[original.length - 32];
      byte[] HMAC_received = new byte[32];
      System.arraycopy(original, 0, message, 0, original.length - 32);
      System.arraycopy(original, original.length - 32, HMAC_received, 0, 32);
      byte[] HMAC = HMAC(key.getEncoded(), message);
      // check if HMAC and received HMAC are the same, as when receiving MAC
      for (int j = 0; j < HMAC_received.length; j++) {
        if (HMAC_received[i] != HMAC[i]) {
          System.out.println("error: received HMAC and HMAC are not the same");
          System.exit(1);
        }
      }
      // remove extra 0s at the end of the message byte array
      ArrayList<Byte> messageList = new ArrayList<>();
      for (byte b : message) {
        if (b != (byte) 0) messageList.add(b);
      }
      byte[] realMessage = new byte[messageList.size()];
      for (int k = 0; k < messageList.size(); k++) {
        realMessage[k] = messageList.get(k);
      }
      baos.write(realMessage);
    }
    byte[] array = baos.toByteArray();
    return new String(array, StandardCharsets.UTF_8);
  }

  private static byte[] hkdfExpand(byte[] key, String tag) throws InvalidKeyException, NoSuchAlgorithmException {
    byte[] okm = HMAC(key, concatenateByte(tag));
    return Arrays.copyOfRange(okm, 0, 16); // the first 16 bytes
  }

  /**
   * Gets the RSA public key for signature verification
   *
   * @param certificateBytes certificate in byte array
   * @return RSA public key from the certificate
   * @throws CertificateException CertificateException
   */
  private static PublicKey getRSAPubKey(byte[] certificateBytes) throws CertificateException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    InputStream certificateInputStream = new ByteArrayInputStream(certificateBytes);
    Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);
    return certificate.getPublicKey();
  }

  /**
   * Gets public key from the CA certificate
   *
   * @return public key
   * @throws FileNotFoundException FileNotFoundException
   * @throws CertificateException  CertificateException
   */
  private static PublicKey getCAPublicKey() throws IOException, CertificateException {
    InputStream is = new FileInputStream("CAcertificate.pem");
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    InputStream certificateIs = new ByteArrayInputStream(is.readAllBytes());
    return cf.generateCertificate(certificateIs).getPublicKey();
  }

  /**
   * Gets certificate from stream
   *
   * @param certificate certificate byte array read from stream
   * @return certificate
   * @throws CertificateException CertificateException
   */
  private static Certificate getCertificate(byte[] certificate) throws CertificateException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    InputStream is = new ByteArrayInputStream(certificate);
    return cf.generateCertificate(is);
  }

  /**
   * Helper method to send byte array to the client
   *
   * @param socket client socket
   * @param bytes  byte array to be sent
   * @throws IOException IOException
   */
  private static void sendBytes(Socket socket, byte[] bytes) throws IOException {
    DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
    dos.writeInt(bytes.length); // used for receiver to know the length of message
    dos.write(bytes); // the actual message that has the length of length
  }

  /**
   * Helper method to receive byte array message
   *
   * @param socket socket from which bytes are sent
   * @return message received
   * @throws IOException IOException
   */
  private static byte[] receiveBytes(Socket socket) throws IOException {
    DataInputStream dis = new DataInputStream(socket.getInputStream());
    int length = dis.readInt();
    if (length > 0) {
      byte[] message = new byte[length];
      dis.readFully(message, 0, message.length);
      return message;
    }
    return null;
  }

  /**
   * Helper method to concatenates the tag with a byte with value 1
   *
   * @param tag string to be concatenated with
   * @return concatenated byte array
   */
  private static byte[] concatenateByte(String tag) {
    byte[] res = new byte[tag.length() + 1];
    byte[] original = tag.getBytes();
    System.arraycopy(original, 0, res, 0, original.length);
    // Add a byte with value 1 to the end of tag
    res[tag.length()] = (byte) 1;
    return res;
  }
}