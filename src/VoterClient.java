import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.util.Calendar;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JRadioButton;
import javax.swing.JTextField;
import javax.swing.JOptionPane;

/**
 *
 * @author Vidhi
 */
public class VoterClient extends JFrame implements ActionListener {

    private final String host = "localhost";
    private final int port = 8080;
    private PrintWriter socketOut;
    private BufferedReader socketIn;
    private final int currentYear = 2018;
    private final String serverAddress = "localhost";

    static final String KEYSTORE = "scr/ElectionKey.jks";
    static final String TRUSTSTORE = "scr/TrustStore.jks";
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
    private static JRadioButton party4;

    private static JTextField nameField;
    private static JTextField yearField;
    private static JTextField monthField;
    private static JTextField dayField;
    private static JTextField voteCode;

    private static JLabel writeName;
    private static JLabel writeYear;
    private static JLabel writeMonth;
    private static JLabel writeDay;

    private static boolean noConnectionCLA = false;		// used to display if the CLA server is not connected
    private static boolean noConnectionCTF = false;		// used to display if the CTF server is not connected

    VoterClient() {
        //Initialize the frame layout
        initJFrame();
    }

    /*VoterClient(InetAddress host, int port)
     {
     this.host = host;
     this.port = port;
     }
     */
    public static void main(String[] args) {
        VoterClient vc = new VoterClient();
        //vc.runCLA(KEYSTORE);

    }

    /**
     * Running the CLA server to get the validation code
     * @param ssn 
     */
    public void runCLA(String ssn) {
        //Getting validation from the CTF server
        try {
            //Making keys to store the key from keys
            System.out.println("Setting up keys for getting validation: ");
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(KEYSTORE), STORE_PSWD.toCharArray());

            //Storing turstStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE), STORE_PSWD.toCharArray());

            //Generatating and instantiaing keys
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, ALIAS_PSWD.toCharArray());

            //Generating and initiating trust key
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(trustStore);

            //ISSUES with the SSL connection
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            SSLSocketFactory sslFact = sslContext.getSocketFactory();
            SSLSocket client = (SSLSocket) sslFact.createSocket(host, port);
            client.setEnabledCipherSuites(client.getSupportedCipherSuites());

            System.out.println("\n>>>> Voter client <-> CLA SSL/TLS handshake completed");

            socketIn = new BufferedReader(new InputStreamReader(client.getInputStream()));
            socketOut = new PrintWriter(client.getOutputStream(), true);

            BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));

            socketOut.println("VoterClient");
            socketOut.println(ssn);
            System.out.println("Voter client sending SSN " + ssn + " to CLA server");

            String validationCode = socketIn.readLine();
            System.out.println("Voter client received validation number " + validationCode + " from the CLA server");
            if (!validationCode.equals("")) {
                //txtFieldDisplayCode.setText(validationCode);
            }

            // Stop loop on server
            socketOut.println("");
            noConnectionCLA = false;

        } catch (Exception e) {

        }
    }

    //Initializing the frame
    private void initJFrame() {
        mainFrame = new JFrame("Voter");

        getCode = new JButton("Get code");
        vote = new JButton("Vote");
        exit = new JButton("Exit");
        butnVoteCode = new JButton("Verify");
        back = new JButton("Back");
        castVote = new JButton("Vote");

        party1 = new JRadioButton("Party1");
        party2 = new JRadioButton("Party2");
        party3 = new JRadioButton("Party3");
        party4 = new JRadioButton("Party4");

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
        if (e.getSource() == getCode) {
            System.out.println("============ Getting code ============");
            String name = nameField.getText();
            String day = dayField.getText();
            String month = monthField.getText();
            String year = yearField.getText();

            try {
                if (name.isEmpty()) {
                    System.out.println("Error: No name entered");
                    // JOptionPane.showMessageDialog(mainFrame, "Enter in a valid name", "Error", JOptionPane.ERROR_MESSAGE);
                    // System.exit(1);
                } else {
                    Calendar c = Calendar.getInstance();
                    c.setLenient(false);
                    c.clear();
                    c.set(Integer.parseInt(year), Integer.parseInt(month) - 1, Integer.parseInt(day));
                    Calendar today = Calendar.getInstance();

                    today.add(Calendar.YEAR, -18);
                    if (today.before(c)) {
                        System.out.println("Sorry. You need to be at least 18 to vote.");
                        //                System.exit(1);
                    } else {
                        System.out.println("Done getting inputs: ");
                        String voterInfo = name + ": " + year + "-" + month + "-" + day;
                        runCLA(voterInfo); //Issues calling this function
                    }
                }
            } catch (Exception exception) {
                System.out.println("Invalid Date: " + exception.getMessage());
//                JOptionPane.showMessageDialog(mainFrame, "Invalid Date: " + exception.getMessage(), "Error",
//                        JOptionPane.ERROR_MESSAGE);
            }
        } else if (e.getSource() == vote) {
            System.out.println("========= Verifying user ==========");
            removeMainFrameComponents();
            verifyUser();
            runCTF(voteCode.getText()); //Run to verify and allows the user to vote
            if (e.getSource() == butnVoteCode) {
                System.out.println("========= Voting ==========");
                removeVerifyUser();
               
            }
        }
         else if (e.getSource() == back) {
            initJFrame();
        } else if (e.getSource() == exit) {
            System.out.println("========= Quit Button is pressed ==========");
            System.exit(0);
        }
    }

    public void verifyUser() {
        mainFrame.add(butnVoteCode);
        mainFrame.add(back);
        mainFrame.add(voteCode);
        //writeVoteCode.setVisible(true);

        mainFrame.repaint();
        mainFrame.validate();

    }

    public void removeVerifyUser() {
        butnVoteCode.setVisible(false);
        voteCode.setVisible(false);
        back.setVisible(false);
        
        mainFrame.repaint();
        mainFrame.validate();
    }

    public void castVote() {
        System.out.println("Setting up the radio buttons");

        //Grouping radio buttons
        ButtonGroup group = new ButtonGroup();
        group.add(party1);
        group.add(party2);
        group.add(party3);
        group.add(party4);

        party1.addActionListener(this);
        party2.addActionListener(this);
        party3.addActionListener(this);
        party4.addActionListener(this);

        mainFrame.add(castVote);
        mainFrame.add(party1);
        mainFrame.add(party2);
        mainFrame.add(party3);
        mainFrame.add(party4);

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
        //Call the CTF to confirm user code 
        try {
            //Making keys to store the key from keys
            System.out.println("Setting up keys for getting validation: ");
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(KEYSTORE), STORE_PSWD.toCharArray());

            //Storing turstStore
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(new FileInputStream(TRUSTSTORE), STORE_PSWD.toCharArray());

            //Generatating and instantiaing keys
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, ALIAS_PSWD.toCharArray());

            //Generating and initiating trust key
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
            trustManagerFactory.init(trustStore);

            //ISSUES with the SSL connection
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
            SSLSocketFactory sslFact = sslContext.getSocketFactory();
            SSLSocket client = (SSLSocket) sslFact.createSocket(host, port);
            client.setEnabledCipherSuites(client.getSupportedCipherSuites());

            System.out.println("\n>>>> Voter client <-> CTF SSL/TLS handshake completed");

            socketIn = new BufferedReader(new InputStreamReader(client.getInputStream()));
            socketOut = new PrintWriter(client.getOutputStream(), true);

            BufferedReader bufferRead = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Voter client sending validation code " + valCode + " to CTF server");
			socketOut.println(valCode);
			
			int voterCase = Integer.parseInt(socketIn.readLine());
			if(voterCase == 0){
				JOptionPane.showMessageDialog(null, "Invalid code!");
				socketOut.println("IngetParti");
			} else if(voterCase == 1) {	
                            // the voter has not already voted
				 castVote();
			} else if(voterCase == 2) {
				String tmp = socketIn.readLine();
				JOptionPane.showMessageDialog(null, "You have already voted! You voted for " + tmp);
				socketOut.println("IngetParti");
				//displayVoteResults();
			} else {
				System.out.println("RunCTF ERROR!");
			}
			
			
			noConnectionCTF = false;
        }
        catch(Exception e){}
        castVote();
    }

}
