import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ConnectException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Client {
    private static Socket socket;

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, InvalidKeyException, SignatureException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException {
        try {
            socket = new Socket("127.0.0.1", 8080);
            System.out.println("connection succeeded");
        } catch (ConnectException e) {
            System.out.println("error: need to run the server first");
            System.exit(1);
        }

        // Handshake starts
        // Steps below follow the assignment instruction. See also Server.java

        System.out.println("handshake starts");
        // all handshake messages for sending MAC
        ByteArrayOutputStream messages = new ByteArrayOutputStream(); // init

        // 1, Client send Nonce1 (32 bytes from a SecureRandom object)
        byte[] nonce = generateNonce();
        sendBytes(socket, nonce);
        messages.writeBytes(nonce);
        // Server receives Nonce1 from client - see Server.java

        // 2, Server: - see Server.java
        // (sends) Server Certificate
        // (sends) Diffie-Hellman public key
        // (sends) Signed Diffie-Hellman public key (Sign[g^ks % N, Spriv])
        // Client verifies server signature
        DiffieHellman.serverPublicKey = DiffieHellman.verifyPublicKey(socket, messages);

        // Step 3: Client:
        // 1. (sends) Client Certificate
        byte[] certificateBytes = new FileInputStream("CASignedClientCertificate.pem").readAllBytes();
        sendBytes(socket, certificateBytes);
        messages.writeBytes(certificateBytes);
        // 2. (sends) Diffie-Hellman public key
        BigInteger kc = DiffieHellman.generatePrivateKey();
        BigInteger g = DiffieHellman.g; // same for the server
        BigInteger n = new BigInteger(DiffieHellman.MODPString, 16); // same for the server
        DiffieHellman.clientPublicKey = DiffieHellman.generatePublicKey(g, kc, n).toByteArray();
        sendBytes(socket, DiffieHellman.clientPublicKey);
        messages.writeBytes(DiffieHellman.clientPublicKey);
        // 3. (sends) Signed DiffieHellman public key (Sign[g^kc % N, Cpriv])
        PrivateKey RSA_privateKey = loadRSASecretKey();
        DiffieHellman.signedClientPublicKey = DiffieHellman.signPublicKey(DiffieHellman.clientPublicKey, RSA_privateKey);
        sendBytes(socket, DiffieHellman.signedClientPublicKey);
        messages.writeBytes(DiffieHellman.signedClientPublicKey);

        // 4, Client and Server compute the shared secret using Diffie-Hellman
        byte[] DHSharedSecret = DiffieHellman.generateSharedSecret(DiffieHellman.serverPublicKey, kc, n).toByteArray();

        // 5, Client and Server derive 6 session keys from the shared secret
        // 2 each of bulk encryption keys, MAC keys, IVs for CBC using HKDF
        byte[] prk = DiffieHellman.HMAC(nonce, DHSharedSecret);
        SecretKeySpec serverEncrypt = DiffieHellman.generateServerEncrypt(prk);
        SecretKeySpec clientEncrypt = DiffieHellman.generateClientEncrypt(serverEncrypt);
        SecretKeySpec serverMAC = DiffieHellman.generateServerMAC(clientEncrypt);
        SecretKeySpec clientMAC = DiffieHellman.generateClientMAC(serverMAC);
        IvParameterSpec serverIV = DiffieHellman.generateServerIV(clientMAC);
        IvParameterSpec clientIV = DiffieHellman.generateClientIV(serverIV);

        // 6, Server: - see Server.java
        // Client receives MAC (all handshake messages so far, Server's MAC key)
        DiffieHellman.receiveMAC(socket, serverMAC, messages);

        // 7, Client sends MAC (all handshake messages so far including the previous step, Client's MAC key)
        DiffieHellman.sendMAC(socket, clientMAC, messages);
        // Server - see Server.java

        // handshake finished
        System.out.println("handshake finished");

        // receives the 1st message from the server:
        String message = DiffieHellman.receiveMessage(socket, clientMAC, clientIV);
        System.out.println("received message from server: " + message);

        // receives the 2nd message from the server:
        String message1 = DiffieHellman.receiveMessage(socket, clientMAC, clientIV);
        System.out.println("received message from server: " + message1);

        // receive the 3rd message, which is a text file
        FileOutputStream fos = new FileOutputStream("file_received.txt");
        fos.write(DiffieHellman.receiveMessage(socket, serverMAC, serverIV).getBytes(StandardCharsets.UTF_8));
        System.out.println("received a file from the server");

        // sends ACK to close the connection
        DiffieHellman.sendMessage(socket, "ACK", clientMAC, clientIV);
        System.out.println("sent an ACK to the server");
    }

    /**
     * Helper method to send byte array to the client
     *
     * @param socket socket
     * @param bytes  byte array to be sent
     * @throws IOException IOException
     */
    private static void sendBytes(Socket socket, byte[] bytes) throws IOException {
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        dos.writeInt(bytes.length);
        dos.write(bytes);
    }

    /**
     * Helper method for loading the RSA secret key from file
     *
     * @return the RSA secret key for signing
     * @throws IOException              IOException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws InvalidKeySpecException  InvalidKeySpecException
     */
    private static PrivateKey loadRSASecretKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = new FileInputStream("clientPrivateKey.der").readAllBytes();
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    /**
     * Generates client nonce to be sent to the server
     *
     * @return nonce in byte array
     */
    private static byte[] generateNonce() { // TODO: shouldn't in the superclass if refactored
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return bytes;
    }
}
