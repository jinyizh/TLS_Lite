import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Server {
    public static void main(String[] args) throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchProviderException {
        ServerSocket serverSocket = new ServerSocket(8080);
        System.out.println("waiting for client to connect");
        Socket clientSocket = serverSocket.accept();
        System.out.println("connection succeeded");

        // Handshake starts.
        // Steps below follow the assignment instruction. See also Client.java

        // all handshake messages for sending MAC
        ByteArrayOutputStream messages = new ByteArrayOutputStream(); // init

        // 1, Client sends Nonce1 (32 bytes from a SecureRandom object) - see Client.java
        // Server receives Nonce1 from client
        byte[] nonce = receiveBytes(clientSocket); // from the client
        messages.writeBytes(nonce);

        // 2, Server:
        // (sends) Server Certificate
        byte[] ServerCertificateBytes = new FileInputStream("CASignedServerCertificate.pem").readAllBytes();
        sendBytes(clientSocket, ServerCertificateBytes);
        messages.writeBytes(ServerCertificateBytes);
        // (sends) Diffie-Hellman public key
        BigInteger ks = DiffieHellman.generatePrivateKey();
        BigInteger g = DiffieHellman.g; // same for the client
        BigInteger n = new BigInteger(DiffieHellman.MODPString, 16); // same for the client
        DiffieHellman.serverPublicKey = DiffieHellman.generatePublicKey(g, ks, n).toByteArray();
        sendBytes(clientSocket, DiffieHellman.serverPublicKey);
        messages.writeBytes(DiffieHellman.serverPublicKey);
        // (sends) Signed DiffieHellman public key (Sign[g^ks % N, Spriv])
        PrivateKey RSAPrivateKey = loadRSASecretKey();
        DiffieHellman.signedServerPublicKey = DiffieHellman.signPublicKey(DiffieHellman.serverPublicKey, RSAPrivateKey);
        sendBytes(clientSocket, DiffieHellman.signedServerPublicKey);
        messages.writeBytes(DiffieHellman.signedServerPublicKey);
        // Client verifies server signature - see Client.java

        // 3, Client: - see Client.java
        // (sends) Client Certificate
        // (sends) Diffie-Hellman public key
        // (sends) Signed Diffie-Hellman public key (Sign[g^kc % N, Cpriv])
        // Server read and verify client's signature:
        DiffieHellman.clientPublicKey = DiffieHellman.verifyPublicKey(clientSocket, messages);

        // 4, Client and Server compute the shared secret using Diffie-Hellman
        byte[] DHSharedSecret = DiffieHellman.generateSharedSecret(DiffieHellman.clientPublicKey, ks, n).toByteArray();

        // 5, Client and Server derive 6 session keys from the shared secret
        // 2 each of bulk encryption keys, MAC keys, IVs for CBC using HKDF
        byte[] prk = DiffieHellman.HMAC(nonce, DHSharedSecret);
        SecretKeySpec serverEncrypt = DiffieHellman.generateServerEncrypt(prk);
        SecretKeySpec clientEncrypt = DiffieHellman.generateClientEncrypt(serverEncrypt);
        SecretKeySpec serverMAC = DiffieHellman.generateServerMAC(clientEncrypt);
        SecretKeySpec clientMAC = DiffieHellman.generateClientMAC(serverMAC);
        IvParameterSpec serverIV = DiffieHellman.generateServerIV(clientMAC);
        IvParameterSpec clientIV = DiffieHellman.generateClientIV(serverIV);

        // 6, Server sends MAC (all handshake messages so far, Server's MAC key)
        DiffieHellman.sendMAC(clientSocket, serverMAC, messages);
        // Client - see Client.java

        // 7, Client: - see Client.java
        // Server receives MAC (all handshake messages so far including the previous step, Client's MAC key)
        DiffieHellman.receiveMAC(clientSocket, clientMAC, messages);

        // handshake finished
        System.out.println("handshake finished");

        // sends the 1st message
        DiffieHellman.sendMessage(clientSocket, "this is the first message from the client!", clientMAC, clientIV);
        System.out.println("sent a message to the client");

        // sends the 2nd message
        DiffieHellman.sendMessage(clientSocket, "this is the second message from the client!!", clientMAC, clientIV);
        System.out.println("sent a message to the client");

        // sends the 3rd message, which is a text file
        InputStream inputStream = new FileInputStream("file_sent.txt");
        String text = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        DiffieHellman.sendMessage(clientSocket, text, serverMAC, serverIV);
        System.out.println("sent a file to the client");

        // receives ACK and closes the connection
        String message = DiffieHellman.receiveMessage(clientSocket, clientMAC, clientIV);
        if (message.equals("ACK")) {
            System.out.println("received an ACK from the client, exiting the program now...");
            System.exit(0);
        }
        System.out.println("received message: " + message);
    }

    /**
     * Helper method to send byte array to the client
     * @param socket socket
     * @param bytes byte array to be sent
     * @throws IOException IOException
     */
    private static void sendBytes(Socket socket, byte[] bytes) throws IOException {
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        dos.writeInt(bytes.length); // used for receiver to know the length of message
        dos.write(bytes); // the actual message that has the length of length
    }

    /**
     * Helper method for loading the RSA secret key from file
     * @return the RSA secret key for signing
     * @throws IOException IOException
     * @throws NoSuchAlgorithmException NoSuchAlgorithmException
     * @throws InvalidKeySpecException InvalidKeySpecException
     */
    private static PrivateKey loadRSASecretKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] bytes = new FileInputStream("serverPrivateKey.der").readAllBytes();
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    /**
     * Note: TODO: shouldn't in the superclass if refactored
     * @param socket client socket
     * @return message in byte array from client socket
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
}
