
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;

/**
 *
 * @author Vidhi
 */
public class VoterClient extends JFrame implements ActionListener {

    private InetAddress host;
    private int port = 8080;
    static final int DEFAULT_CLA_PORT = 8188;
    static final int DEFAULT_CTF_PORT = 8189;

    private PrintWriter socketOut;
    private BufferedReader socketIn;

    static Socket client = null;
    static DataOutputStream CLA_Output;
    static DataInputStream CLA_Input;
    static DataOutputStream CTF_Output;
    static DataInputStream CTF_Input;
    private static EncryptRSA rsa_Cipher;
    private static EncryptDES DES_Key = null;

    static final String KEYSTORE = "src/ElectionKey.jks";
    static final String TRUSTSTORE = "src/TrustStore.jks";
    static final String STORE_PSWD = "coe817";
    static final String ALIAS_PSWD = "coe817";

    //Frame layout
    JFrame mainFrame;
    private static JButton getCode;
    private static JButton vote;
    private static JButton exit;
    private static JButton butnVoteCode;
    private static JButton castVote;
    private static JButton back;
    private static JRadioButton party1;
    private static JRadioButton party2;
    private static JRadioButton party3;

    private static JTextField nameField;
    private static JTextField yearField;
    private static JTextField monthField;
    private static JTextField dayField;
    private static JTextField voteCode;

    private static JLabel writeName;
    private static JLabel writeYear;
    private static JLabel writeMonth;
    private static JLabel writeDay;

    VoterClient() {
        //Initialize the frame layout
        initJFrame();
    }

    VoterClient(InetAddress host, int port) {
        this.host = host;
        this.port = port;
    }

    public static void main(String[] args) {
        VoterClient vc = new VoterClient();
    }

    /**
     * Running the CLA server to get the validation code
     *
     * @param ssn
     */
    public void runCLA(String ssn) {
        String input = "";
        boolean validConnection = false;

        if (DES_Key == null) {
            try {
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(null);
                client = new Socket("127.0.0.1", 9999);
                CLA_Output = new DataOutputStream(client.getOutputStream());
                CLA_Input = new DataInputStream(client.getInputStream());

                rsa_Cipher = new EncryptRSA();
                PublicKey serverPublicRSAKey;
                EncryptRSA serverPublicRSA;

                SecretKey privateKey = KeyGenerator.getInstance("DES").generateKey();
                DES_Key = new EncryptDES(privateKey);

//            System.out.println("Decoded Public Key: " + Arrays.toString(rsa_Cipher.PUB_KEY.getEncoded()));
                String encodedKey = Base64.getEncoder().encodeToString(rsa_Cipher.PUB_KEY.getEncoded());
                CLA_Output.writeUTF(encodedKey);
//            System.out.println("Sent Encoded Public Key: " + encodedKey);

                input = CLA_Input.readUTF();
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
                CLA_Output.writeUTF(encryptedMessage);
//            System.out.println("Sent Encrypted M1: " + encryptedMessage);

                //Read in response from server
                input = CLA_Input.readUTF();
//            System.out.println("Received M2: " + input);
                String decryptedInput = rsa_Cipher.decrypt(input, rsa_Cipher.PRIV_KEY);
//            System.out.println("Decrypted M2: " + decryptedInput);

                //Check if the server returned nonce1 verifying that it is the one sending this message
                if (decryptedInput.split("~")[0].equals(nonce1)) {
//                System.out.println("Nonce1 Matches: " + nonce1 + " = " + decryptedInput.split("~")[0]);

                    String nonce2 = decryptedInput.split("~")[1];
                    encryptedMessage = serverPublicRSA.encrypt(nonce2, serverPublicRSAKey);
//                System.out.println("Sending M3: " + nonce2);
                    CLA_Output.writeUTF(encryptedMessage);
//                System.out.println("Sent Encrypted M3: " + encryptedMessage);

//                System.out.println("Decoded Private DES Key: " + Arrays.toString(privateKey.getEncoded()));
                    encodedKey = rsa_Cipher.encrypt(Base64.getEncoder().encodeToString(privateKey.getEncoded()), rsa_Cipher.PRIV_KEY);
                    String keyPart1 = serverPublicRSA.encrypt(encodedKey.substring(0, encodedKey.length() / 2), serverPublicRSAKey);
                    String keyPart2 = serverPublicRSA.encrypt(encodedKey.substring(encodedKey.length() / 2), serverPublicRSAKey);
                    CLA_Output.writeUTF(keyPart1);
//                System.out.println("Sent Part 1 Encrypted Encoded Private DES Key: " + keyPart1);
                    CLA_Output.writeUTF(keyPart2);
//                System.out.println("Sent Part 2 Encrypted Encoded Private DES Key: " + keyPart2 + "\n");
                    validConnection = true;
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
            }
            System.out.println("Connected to CLA Server");
        } else {
            validConnection = true;
        }
        if (validConnection) {
            try {
                String sentSSN = ssn + "~~" + Hash(ssn);

                System.out.println("Voter info sent to CLA Server");
                CLA_Output.writeUTF(DES_Key.encrypt(sentSSN));
                input = CLA_Input.readUTF();
                String decryptedInput = DES_Key.decrypt(input);

                if (!decryptedInput.split("~~")[0].equals("-1")) {
                    System.out.println("Your validation number is " + decryptedInput.split("~~")[0]);
                } else {
                    System.out.println("Data integrity compromised. Please try again");
                }
            } catch (Exception ex) {
                System.out.println("Error: " + ex.getMessage());
            }
        }
    }

    //Initializing the frame
    private void initJFrame() {
        mainFrame = new JFrame("Voter");

        getCode = new JButton("Get code");
        vote = new JButton("Vote");
        exit = new JButton("Exit");
        back = new JButton("Back");
        castVote = new JButton("Vote");

        party1 = new JRadioButton("Party 1");
        party2 = new JRadioButton("Party 2");
        party3 = new JRadioButton("Party 3");

        //Setting up the field to make sure user is over 18 to vote
        nameField = new JTextField(5);
        yearField = new JTextField(5);
        monthField = new JTextField(5);
        dayField = new JTextField(5);
        voteCode = new JTextField(20);

        writeName = new JLabel("Name: ");
        writeYear = new JLabel("Enter your Birthday      Year");
        writeMonth = new JLabel("Month: ");
        writeDay = new JLabel("Day: ");

        mainFrame.setLayout(new FlowLayout());

        mainFrame.add(writeName);
        mainFrame.add(nameField);
        mainFrame.add(writeYear);
        mainFrame.add(yearField);
        mainFrame.add(writeMonth);
        mainFrame.add(monthField);
        mainFrame.add(writeDay);
        mainFrame.add(dayField);

        mainFrame.add(getCode);
        mainFrame.add(vote);
        mainFrame.add(exit);

        getCode.addActionListener(this);
        vote.addActionListener(this);
        exit.addActionListener(this);

        mainFrame.pack();
        mainFrame.setVisible(true);

    }

    @Override
    public void actionPerformed(ActionEvent e) {
        System.out.println("============ In ActionPerfromed ============");
        //Taking input to verify the user and get the code
        if (e.getSource() == getCode) {
            System.out.println("============ Getting code ============");
            String name = nameField.getText();
            String day = dayField.getText();
            String month = monthField.getText();
            String year = yearField.getText();
            String voterInfo = null;
            try {
                if (name.isEmpty()) {
                    System.out.println("Error: No name entered");
                } else {
                    Calendar c = Calendar.getInstance();
                    c.setLenient(false);
                    c.clear();
                    c.set(Integer.parseInt(year), Integer.parseInt(month) - 1, Integer.parseInt(day));
                    Calendar today = Calendar.getInstance();
                    System.out.println("User Info: " + name + " - "
                            + c.getTime().toString().replaceAll(" \\d\\d:\\d\\d:\\d\\d \\w\\w\\w ", " "));
                    today.add(Calendar.YEAR, -18);
                    if (today.before(c)) {
                        System.out.println("Sorry. You need to be at least 18 to vote.");
                    } else {
                        voterInfo = name + ": " + year + "-" + month + "-" + day;
                        runCLA(voterInfo);
                    }
                }

            } catch (Exception exception) {
                System.out.println("Invalid Date: " + exception.getMessage());
            }
        }
        else if (e.getSource() == vote) {
            System.out.println("========= Verifying user ==========");
            removeMainFrameComponents();
            verifyUser();
            castVote();
        } else if (e.getSource() == castVote) {
            try {
                int vote = 0;
                if (party1.isSelected()) {
                    vote = 1;
                } else if (party2.isSelected()) {
                    vote = 2;
                } else if (party3.isSelected()) {
                    vote = 3;
                }
                System.out.println("Vote: " + vote + "\nVote Code: " + voteCode.getText());
                if (vote != 0) {
                    CLA_Output.writeUTF(DES_Key.encrypt("CTF|||" + voteCode.getText() + "~~" + vote
                            + "~~" + Hash(voteCode.getText() + "~~" + vote)));
                    
                    String[] decryptedInput = DES_Key.decrypt(CLA_Input.readUTF()).split("~~");
                    if (decryptedInput[1].equals(Hash(decryptedInput[0]))){
                        System.out.println("Response from CTF Server: " + decryptedInput[0]);
                    }
                } else {
                    System.out.println("No party selected");
                }
            } catch (Exception ex) {
                System.out.println("Error: " + ex.getMessage());
            }
        } else if (e.getSource() == back) {
            initJFrame();
        } else if (e.getSource() == exit) {
            System.out.println("========= Quit Button is pressed ==========");
            System.exit(0);
        }
    }

    public void verifyUser() {
//        mainFrame.add(butnVoteCode);
        mainFrame.add(back);
        mainFrame.add(voteCode);

//        butnVoteCode.addActionListener(this);
        back.addActionListener(this);
        voteCode.addActionListener(this);
        //writeVoteCode.setVisible(true);

        mainFrame.repaint();
        mainFrame.validate();

    }

    public void removeVerifyUser() {
//        butnVoteCode.setVisible(false);
        voteCode.setVisible(false);
        back.setVisible(false);

        /* mainFrame.repaint();
        mainFrame.validate();*/
    }

    public void castVote() {
        //Grouping radio buttons
        ButtonGroup group = new ButtonGroup();
        group.add(party1);
        group.add(party2);
        group.add(party3);

        castVote.addActionListener(this);

        mainFrame.add(castVote);
        mainFrame.add(party1);
        mainFrame.add(party2);
        mainFrame.add(party3);

        mainFrame.repaint();
        mainFrame.validate();
    }

    public void removeMainFrameComponents() {
        nameField.setVisible(false);
        yearField.setVisible(false);
        monthField.setVisible(false);
        dayField.setVisible(false);

        writeName.setVisible(false);
        writeYear.setVisible(false);
        writeMonth.setVisible(false);
        writeDay.setVisible(false);

        getCode.setVisible(false);
        vote.setVisible(false);
        //  exit.setVisible(false);
    }

    public void runCTF(String valCode) {
        String input = "";
        boolean validConnection = false;

        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null);
            client = new Socket("127.0.0.1", 49681);
            CTF_Output = new DataOutputStream(client.getOutputStream());
            CTF_Input = new DataInputStream(client.getInputStream());
            validConnection = true;
            System.out.println("Connected to CTF Server");
//                }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
        }

        if (validConnection) {
            try {
                CTF_Output.writeUTF(DES_Key.encrypt(valCode + "~~" + Hash(valCode)));
            } catch (Exception ex) {
                System.out.println("Error: " + ex.getMessage());
            }
        }
        castVote();
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
}
