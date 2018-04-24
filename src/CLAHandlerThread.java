
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.Socket;
import java.util.HashMap;

public class CLAHandlerThread extends Thread {

    protected Socket socket;
    private BufferedReader in;
    private PrintWriter out;

    // Inner class VoterPublicKey
    public class VoterPublicKey {

        private String ssn;
        private BigInteger e, n;

        VoterPublicKey(BigInteger e, BigInteger n, String ssn) {
            this.ssn = ssn;
            this.n = n;
            this.e = e;
        }

        public BigInteger getE() {
            return this.e;
        }

        public BigInteger getN() {
            return this.n;
        }

        public String getSSN() {
            return this.ssn;
        }
    }

    // Hash map containing valid voter social security numbers and their corresponding public keys
    static HashMap<String, String> voterValidationCodes = new HashMap<String, String>();				// <ssn, validationCode>
    static HashMap<String, VoterPublicKey> voterPublicKeys = new HashMap<String, VoterPublicKey>();

    ;	// <ssn, voterPublicKey>// <ssn, voterPublicKey>

	/**
	 * Constructor
	 * @param clientSocket
	 */
    public CLAHandlerThread(Socket clientSocket) {
        this.socket = clientSocket;

        // Set up valid voters. TODO: static - will these be added once for each thread?
        voterPublicKeys.put("123", new VoterPublicKey(new BigInteger("17"), new BigInteger("551"), "123"));
        voterPublicKeys.put("456", new VoterPublicKey(new BigInteger("7"), new BigInteger("253"), "456"));
        voterPublicKeys.put("789", new VoterPublicKey(new BigInteger("5"), new BigInteger("119"), "789"));
    }

    public void run() {
        try {
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            // ===== Secure election ===== //
            //while(true)
            //{
            // Check if the client is a voter or DTFServer
            String clientName = in.readLine();

            System.out.println("CLA handler received client name: " + clientName + " in socket!");

            // If contacted by VoterClient
            if (clientName.equals("VoterClient")) {
                System.out.println("CLA server contacted by voter client!");
                String ssn = in.readLine();
                System.out.println("Server received SSN " + ssn + " from client");
                String validationCode = "";

                // Check if the ssn is valid
                if (voterPublicKeys.containsKey(ssn)) {
                    // check if a validation number already has been created for this ssn
                    if (voterValidationCodes.containsKey(ssn)) {
                        // get the value of key 'ssn'
                        validationCode = voterValidationCodes.get(ssn);
                    } else {
                        // create a random validationCode
                        validationCode = generatevalidationCode();
                        System.out.println("CLA adding ssn and validationCode " + ssn + ", " + validationCode + " to hash map!");
                        voterValidationCodes.put(ssn, validationCode);
                        // only used to show what is saved and to whom.
                        createASaveFile(voterValidationCodes);

                        System.out.println("Result: " + voterValidationCodes.toString());
                    }

                    // Print the validation number back to the voter client
                    out.println(validationCode);
                    System.out.println("CLA sending validation code " + validationCode + " to voter client");

                } else {
                    // Not a valid ssn
                    System.out.println(ssn + " is not a valid ssn!");
                    out.println(ssn + " is not a valid ssn!");
                }

                System.out.println("Closing voter client connection to CLA server!");
                //incoming.close();
            } // if CTFServer
            else if (clientName.equals("CTFServer")) {
                String valCode = in.readLine();
                System.out.println("CLA server received " + valCode + " from CTF server!");
                boolean codeIsValid = voterValidationCodes.containsValue(valCode);
                System.out.println("CLA sending validCode = " + codeIsValid + " to CTF server!");
                out.println(codeIsValid);
            }
            //}
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    /*
	 * Generate a random validation number.
     */
    private String generatevalidationCode() {
        int randomInt = (int) Math.round(Math.random() * 20000);
        return Integer.toString(randomInt);
    }

    private void createASaveFile(HashMap<String, String> voterValidationCodes2) {
        File file = new File("txt/CLA_voters_and_codes.txt");
        BufferedWriter writer;
        try {
            writer = new BufferedWriter(new FileWriter(file));
            writer.write(voterValidationCodes2.toString());
            writer.close();
        } catch (IOException e) {

        }
    }

}
