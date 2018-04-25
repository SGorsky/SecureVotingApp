
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
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
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

    static Socket client = null;
    static DataInputStream voterInput;
    static DataOutputStream voterOutput;
    static DataOutputStream CTF_Output;
    static DataInputStream CTF_Input;
    private static EncryptRSA rsa_Cipher;
    private static SecretKey secretKey = null;
    private static EncryptDES DES_Key = null;
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
            voterOutput = new DataOutputStream(clientSocket.getOutputStream());
            voterInput = new DataInputStream(clientSocket.getInputStream());

            rsa_Cipher = new EncryptRSA();
            PublicKey clientPublicRSAKey;
            EncryptRSA clientPublicRSA;

            //Read in the client's public key
            input = voterInput.readUTF();
//            System.out.println("Received Encoded Key: " + input);
            byte[] decodedKey = Base64.getDecoder().decode(input);
//            System.out.println("Received Decoded Key: " + Arrays.toString(decodedKey));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
            clientPublicRSAKey = KeyFactory.getInstance("RSA").generatePublic(spec);
            clientPublicRSA = new EncryptRSA();

//            System.out.println("Decoded Key: " + Arrays.toString(rsa_Cipher.PUB_KEY.getEncoded()));
            String encodedKey = Base64.getEncoder().encodeToString(rsa_Cipher.PUB_KEY.getEncoded());
            voterOutput.writeUTF(encodedKey);
//            System.out.println("Sent Encoded Key: " + encodedKey);

            //Read in input from client and decrypt it using your public key
            //It should be a nonce and the client's ID
            input = voterInput.readUTF();
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
            voterOutput.writeUTF(encryptedMessage);
//            System.out.println("Sent Encrypted M2: " + encryptedMessage);

            input = voterInput.readUTF();
//            System.out.println("Received M3: " + input);
            decryptedInput = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
//            System.out.println("Decrypted M3: " + decryptedInput);
            if (decryptedInput.equals(nonce2)) {
//                System.out.println("Nonce2 Matches: " + nonce2 + " = " + decryptedInput);

                //Read in the client's private key
                input = voterInput.readUTF();
//                System.out.println("Received Part 1 Encoded Private DES Key: " + input);
                String keyPart1 = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
                input = voterInput.readUTF();
//                System.out.println("Received Part 2 Encoded Private DES Key: " + input);
                String keyPart2 = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
                decodedKey = Base64.getDecoder().decode(clientPublicRSA.decrypt(keyPart1 + keyPart2, clientPublicRSAKey));
//                System.out.println("Received Decoded Private DES Key: " + Arrays.toString(decodedKey));
                secretKey = new SecretKeySpec(decodedKey, "DES");
                DES_Key = new EncryptDES(secretKey);

                validConnection = true;
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }
        System.out.println("Connected to VoterClient");

        if (validConnection && DES_Key != null) {
            while (true) {
                try {
                    input = voterInput.readUTF();
                    String[] decryptedInput = DES_Key.decrypt(input).split(",");
                    String hashSSN = Hash(decryptedInput[0]);
                    if (decryptedInput[1].equals(hashSSN)) {
                        System.out.println("Hashes match. Data integrity preserved");

                        String validationNumber = String.valueOf(decryptedInput[0].hashCode());
                        System.out.println("Validation Number for " + decryptedInput[0].split(":")[0] + " is " + validationNumber);

                        voterOutput.writeUTF(DES_Key.encrypt(validationNumber + "," + Hash(validationNumber)));

                        if (!validationList.containsKey(Integer.valueOf(validationNumber))) {
                            validationList.put(Integer.valueOf(validationNumber), decryptedInput[0]);
                            ConnectToCTFServer(Integer.valueOf(validationNumber));
                        }
                    } else {
                        System.out.println("Hashes do not match. Data integrity breached!");

                        String validationNumber = "-1";
                        voterOutput.writeUTF(DES_Key.encrypt(validationNumber + "," + Hash(validationNumber)));
                    }
                } catch (Exception e) {
                    System.out.println("Error: " + e.getMessage());
                }
            }
        }
    }

    public void ConnectToCTFServer(int validationNumber) {
        String input = "";
        boolean validConnection = false;

        if (DES_Key == null || CTF_Output == null) {
            try {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(null);
                client = new Socket("127.0.0.1", 49681);
                CTF_Output = new DataOutputStream(client.getOutputStream());
                CTF_Input = new DataInputStream(client.getInputStream());

                rsa_Cipher = new EncryptRSA();
                PublicKey serverPublicRSAKey;
                EncryptRSA serverPublicRSA;

//            System.out.println("Decoded Public Key: " + Arrays.toString(rsa_Cipher.PUB_KEY.getEncoded()));
                String encodedKey = Base64.getEncoder().encodeToString(rsa_Cipher.PUB_KEY.getEncoded());
                CTF_Output.writeUTF(encodedKey);
//            System.out.println("Sent Encoded Public Key: " + encodedKey);

                input = CTF_Input.readUTF();
//            System.out.println("Received Encoded Key: " + input);
                byte[] decodedKey = Base64.getDecoder().decode(input);
//            System.out.println("Received Decoded Key: " + Arrays.toString(decodedKey));
                X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
                serverPublicRSAKey = KeyFactory.getInstance("RSA").generatePublic(spec);
                serverPublicRSA = new EncryptRSA();

                //Generate nonce1 and IDA
                String nonce1 = Long.toString(new Date().getTime());
                String IDA = "Client";

                //Combine them together, encrypt them using the Server's public key and send to server
                String message1 = nonce1 + "~" + IDA;
//            System.out.println("Sending M1: " + message1);
                String encryptedMessage = serverPublicRSA.encrypt(message1, serverPublicRSAKey);
                CTF_Output.writeUTF(encryptedMessage);
//            System.out.println("Sent Encrypted M1: " + encryptedMessage);

                //Read in response from server
                input = CTF_Input.readUTF();
//            System.out.println("Received M2: " + input);
                String decryptedInput = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
//            System.out.println("Decrypted M2: " + decryptedInput);

                //Check if the server returned nonce1 verifying that it is the one sending this message
                if (decryptedInput.split("~")[0].equals(nonce1)) {
//                System.out.println("Nonce1 Matches: " + nonce1 + " = " + decryptedInput.split("~")[0]);

                    String nonce2 = decryptedInput.split("~")[1];
                    encryptedMessage = serverPublicRSA.encrypt(nonce2, serverPublicRSAKey);
//                System.out.println("Sending M3: " + nonce2);
                    CTF_Output.writeUTF(encryptedMessage);
//                System.out.println("Sent Encrypted M3: " + encryptedMessage);

//                System.out.println("Decoded Private DES Key: " + Arrays.toString(privateKey.getEncoded()));
                    encodedKey = rsa_Cipher.encrypt(Base64.getEncoder().encodeToString(secretKey.getEncoded()), rsa_Cipher.PRIV_KEY);
                    String keyPart1 = serverPublicRSA.encrypt(encodedKey.substring(0, encodedKey.length() / 2), serverPublicRSAKey);
                    String keyPart2 = serverPublicRSA.encrypt(encodedKey.substring(encodedKey.length() / 2), serverPublicRSAKey);
                    CTF_Output.writeUTF(keyPart1);
//                System.out.println("Sent Part 1 Encrypted Encoded Private DES Key: " + keyPart1);
                    CTF_Output.writeUTF(keyPart2);
//                System.out.println("Sent Part 2 Encrypted Encoded Private DES Key: " + keyPart2 + "\n");
                    validConnection = true;
                    System.out.println("Connected to CTF Server");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
        } else {
            validConnection = true;
        }
        if (validConnection) {
            try {
                String number = String.valueOf(validationNumber);
                CTF_Output.writeUTF(DES_Key.encrypt(number + "," + Hash(number)));
                String[] decryptedInput = DES_Key.decrypt(CTF_Input.readUTF()).split(",");
                
                if (decryptedInput.equals("0")) {
                    System.out.println("Validation Number (" + number + ") successfully stored in CTF Server");
                }
                else if (decryptedInput.equals("-1")){
                    System.out.println("Data integrity of validation number breached between CLA and CTF Server");
                }
            } catch (Exception ex) {
                System.out.println("Error: " + ex.getMessage());
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
        System.out.println("Starting CLA Server!");
        int port = DEFAULT_PORT;
        if (args.length > 0) {
            port = Integer.parseInt(args[0]);
        }
        CLAServer CLAServer = new CLAServer(port);
        CLAServer.run();
    }
}
