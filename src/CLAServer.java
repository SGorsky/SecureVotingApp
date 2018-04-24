
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ssl.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.SecretKeySpec;

public class CLAServer {

    private int port;
//     This is not a reserved port number
    static final int DEFAULT_PORT = 8188;
//    static final String KEYSTORE = "src/LIUkeystore.ks";
//    static final String TRUSTSTORE = "src/LIUtruststore.ks";
//    static final String trustSTOREPASSWD = "abcdef";
//    static final String keySTOREPASSWD = "123456";
//    static final String ALIASPASSWD = keySTOREPASSWD;

    static ServerSocket echoServer = null;
    static Socket clientSocket = null;
    static DataInputStream inputStream;
    static DataOutputStream outputStream;
    private static EncryptRSA rsa_Cipher;
    private static EncryptDES voterClientDES = null;
    private static Hashtable validationList = new Hashtable();

    /**
     * Constructor
     *
     * @param port The port where the server will listen for requests
     */
    CLAServer(int port) {
        this.port = port;
    }

    /**
     * Function run certifies/authenticates voter client, starts the server and processes SSN input
     */
    public void run() {
        String input = "";
        boolean validConnection = false;

        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            echoServer = new ServerSocket(9999);
            clientSocket = echoServer.accept();
            outputStream = new DataOutputStream(clientSocket.getOutputStream());
            inputStream = new DataInputStream(clientSocket.getInputStream());

            rsa_Cipher = new EncryptRSA();
            PublicKey clientPublicRSAKey;
            EncryptRSA clientPublicRSA;

            //Read in the client's public key
            input = inputStream.readUTF();
//            System.out.println("Received Encoded Key: " + input);
            byte[] decodedKey = Base64.getDecoder().decode(input);
//            System.out.println("Received Decoded Key: " + Arrays.toString(decodedKey));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
            clientPublicRSAKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            clientPublicRSA = new EncryptRSA();

//            System.out.println("Decoded Key: " + Arrays.toString(rsa_Cipher.PUB_KEY.getEncoded()));
            String encodedKey = Base64.getEncoder().encodeToString(rsa_Cipher.PUB_KEY.getEncoded());
            outputStream.writeUTF(encodedKey);
//            System.out.println("Sent Encoded Key: " + encodedKey);

            //Read in input from client and decrypt it using your public key
            //It should be a nonce and the client's ID
            input = inputStream.readUTF();
//            System.out.println("Received M1: " + input);
            String decryptedInput = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
//            System.out.println("Received Decrypted M1: "+ decryptedInput);
            String nonce1 = decryptedInput.split("~")[0];
            String IDA = decryptedInput.split("~")[1];

            //Create a new nonce and add it with the client's nonce
            //Encrypt it using the client's public key and send back to the client
            String nonce2 = Long.toString(new Date().getTime());;
            String message2 = nonce1 + "~" + nonce2;
//            System.out.println("Sending M2: "+ message2);
            String encryptedMessage = clientPublicRSA.encrypt(message2, clientPublicRSAKey);
            outputStream.writeUTF(encryptedMessage);
//            System.out.println("Sent Encrypted M2: " + encryptedMessage);

            input = inputStream.readUTF();
//            System.out.println("Received M3: " + input);
            decryptedInput = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
//            System.out.println("Decrypted M3: " + decryptedInput);
            if (decryptedInput.equals(nonce2)) {
//                System.out.println("Nonce2 Matches: " + nonce2 + " = " + decryptedInput);

                //Read in the client's private key
                input = inputStream.readUTF();
//                System.out.println("Received Part 1 Encoded Private DES Key: " + input);
                String keyPart1 = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
                input = inputStream.readUTF();
//                System.out.println("Received Part 2 Encoded Private DES Key: " + input);
                String keyPart2 = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
                decodedKey = Base64.getDecoder().decode(clientPublicRSA.decrypt(keyPart1 + keyPart2, clientPublicRSAKey));
//                System.out.println("Received Decoded Private DES Key: " + Arrays.toString(decodedKey));
                voterClientDES = new EncryptDES(new SecretKeySpec(decodedKey, "DES"));

                validConnection = true;
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
        System.out.println("Connected to VoterClient");

        if (validConnection && voterClientDES != null) {
            while (true) {
                try {
                    input = inputStream.readUTF();
                    String[] decryptedInput = voterClientDES.decrypt(input).split(",");
                    String hashSSN = Hash(decryptedInput[0]);
                    if (decryptedInput[1].equals(hashSSN)) {
                        System.out.println("Hashes match. Data integrity preserved");
                        
                        String validationNumber = String.valueOf(decryptedInput[0].hashCode());
                        System.out.println("Validation Number for " + decryptedInput[0].split(":")[0] + " is " + validationNumber);

                        outputStream.writeUTF(voterClientDES.encrypt(validationNumber + "," + Hash(validationNumber)));
                        validationList.put(Integer.valueOf(validationNumber), decryptedInput[0]);

                    } else {
                        System.out.println("Hashes do not match. Data integrity violated");

                        String validationNumber = "-1";
                        outputStream.writeUTF(voterClientDES.encrypt(validationNumber + "," + Hash(validationNumber)));
                    }
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }
        }
        /*
        try {
            KeyStore ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(KEYSTORE), keySTOREPASSWD.toCharArray());

            KeyStore ts = KeyStore.getInstance("JCEKS");
            ts.load(new FileInputStream(TRUSTSTORE), trustSTOREPASSWD.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, ALIASPASSWD.toCharArray());

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(ts);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLServerSocketFactory sslServerFactory = sslContext.getServerSocketFactory();
            SSLServerSocket sss = (SSLServerSocket) sslServerFactory.createServerSocket(port);
            sss.setEnabledCipherSuites(sss.getSupportedCipherSuites());

            // Client authentication
            sss.setNeedClientAuth(true);

            System.out.println("\n>>>> CLA Server: active ");
            SSLSocket incoming = (SSLSocket)sss.accept();

            // Create a thread for each client connecting to this server
            while (true) {
                try {
                    incoming = (SSLSocket) sss.accept();
                    System.out.println("hej!");
                } catch (IOException e) {
                    System.out.println("I/O error: " + e);
                }
                // new thread for a client
                new CLAHandlerThread(incoming).start();
            }
        } catch (Exception x) {
            System.out.println(x);
            x.printStackTrace();
        }*/
    }

    public String Hash(String string) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(string.getBytes());
            return new String(messageDigest.digest());
        } catch (NoSuchAlgorithmException ex) {
            System.out.println("Error: " + ex.getMessage());
        }
        return string;
    }

    /**
     * main method of class
     *
     * @param args[0] Optional port number in place of the default
     */
    public static void main(String[] args) {
        System.out.println("Starting CLA Server!");
        int port = DEFAULT_PORT;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }
        CLAServer CLAServer = new CLAServer(port);
        CLAServer.run();
    }
}
