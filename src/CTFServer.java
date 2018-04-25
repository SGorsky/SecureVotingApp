
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import javax.net.ssl.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;

public class CTFServer {

    private int port;
    // This is not a reserved port number
    static final int DEFAULT_PORT = 8189;
    static final int DEFAULT_CLA_PORT = 8188;
    static final String KEYSTORE = "src/LIUkeystore.ks";
    static final String TRUSTSTORE = "src/LIUtruststore.ks";
    static final String trustSTOREPASSWD = "abcdef";
    static final String keySTOREPASSWD = "123456";
    static final String ALIASPASSWD = keySTOREPASSWD;

    static DataOutputStream CLA_Output;
    static DataInputStream CLA_Input;
    static DataOutputStream voterOutput;
    static DataInputStream voterInput;
    private static EncryptRSA rsa_Cipher;
    private static EncryptDES DES_Key = null;

    static ServerSocket echoServer = null;
    static Socket CLA_Socket = null;
    static Socket voterSocket = null;

    private static List<Integer> votingResults = new ArrayList<Integer>();
    private static Hashtable<Integer, Boolean> validationList = new Hashtable<Integer, Boolean>();

    /**
     * Constructor
     *
     * @param port The port where the server will listen for requests
     */
    CTFServer(int port) {
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
            echoServer = new ServerSocket(49681);
            CLA_Socket = echoServer.accept();
            CLA_Output = new DataOutputStream(CLA_Socket.getOutputStream());
            CLA_Input = new DataInputStream(CLA_Socket.getInputStream());

            rsa_Cipher = new EncryptRSA();
            PublicKey clientPublicRSAKey;
            EncryptRSA clientPublicRSA;

            //Read in the client's public key
            input = CLA_Input.readUTF();
//            System.out.println("Received Encoded Key: " + input);
            byte[] decodedKey = Base64.getDecoder().decode(input);
//            System.out.println("Received Decoded Key: " + Arrays.toString(decodedKey));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
            clientPublicRSAKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            clientPublicRSA = new EncryptRSA();

//            System.out.println("Decoded Key: " + Arrays.toString(rsa_Cipher.PUB_KEY.getEncoded()));
            String encodedKey = Base64.getEncoder().encodeToString(rsa_Cipher.PUB_KEY.getEncoded());
            CLA_Output.writeUTF(encodedKey);
//            System.out.println("Sent Encoded Key: " + encodedKey);

            //Read in input from client and decrypt it using your public key
            //It should be a nonce and the client's ID
            input = CLA_Input.readUTF();
//            System.out.println("Received M1: " + input);
            String decryptedInput = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
//            System.out.println("Received Decrypted M1: "+ decryptedInput);
            String nonce1 = decryptedInput.split("~")[0];
            String IDA = decryptedInput.split("~")[1];

            //Create a new nonce and add it with the client's nonce
            //Encrypt it using the client's public key and send back to the client
            String nonce2 = Long.toString(new Date().getTime());
            String message2 = nonce1 + "~" + nonce2;
//            System.out.println("Sending M2: "+ message2);
            String encryptedMessage = clientPublicRSA.encrypt(message2, clientPublicRSAKey);
            CLA_Output.writeUTF(encryptedMessage);
//            System.out.println("Sent Encrypted M2: " + encryptedMessage);

            input = CLA_Input.readUTF();
//            System.out.println("Received M3: " + input);
            decryptedInput = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
//            System.out.println("Decrypted M3: " + decryptedInput);
            if (decryptedInput.equals(nonce2)) {
//                System.out.println("Nonce2 Matches: " + nonce2 + " = " + decryptedInput);

                //Read in the client's private key
                input = CLA_Input.readUTF();
//                System.out.println("Received Part 1 Encoded Private DES Key: " + input);
                String keyPart1 = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
                input = CLA_Input.readUTF();
//                System.out.println("Received Part 2 Encoded Private DES Key: " + input);
                String keyPart2 = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
                decodedKey = Base64.getDecoder().decode(clientPublicRSA.decrypt(keyPart1 + keyPart2, clientPublicRSAKey));
//                System.out.println("Received Decoded Private DES Key: " + Arrays.toString(decodedKey));
                DES_Key = new EncryptDES(new SecretKeySpec(decodedKey, "DES"));

                validConnection = true;
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        if (validConnection && DES_Key != null) {
            while (true) {
                try {
                    String[] validationNumber = DES_Key.decrypt(CLA_Input.readUTF()).split(",");
                    int num = Integer.valueOf(validationNumber[0]);

                    if (Hash(validationNumber[0]).equals(validationNumber[1])) {
                        if (!validationList.containsKey(num)) {
                            validationList.put(num, false);
                            System.out.println("Validation Number (" + num + ") stored");
                            CLA_Output.writeUTF(DES_Key.encrypt("0," + Hash("0")));
                        }
                    } else {
                        System.out.println("Data integrity breached. Hashes do not match!\nReceived: " + validationNumber[1]
                                + "\nCalculated: " + Hash(validationNumber[0]));
                        CLA_Output.writeUTF(DES_Key.encrypt("-1," + Hash("-1")));
                    }
                } catch (Exception ioe) {
                    System.out.println("Error: " + ioe.getMessage());
                }
            }
        }
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
        System.out.println("Starting CTF Server!");
        int port = DEFAULT_PORT;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }
        CTFServer CTFServer = new CTFServer(port);
        CTFServer.run();
    }
}
