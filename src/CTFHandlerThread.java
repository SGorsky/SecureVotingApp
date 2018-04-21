import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyStore;
import java.util.HashMap;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class CTFHandlerThread extends Thread
{
	static final int DEFAULT_CLA_PORT = 8188;
	static final String KEYSTORE = "authentication/LIUkeystore.ks";
	static final String TRUSTSTORE = "authentication/LIUtruststore.ks";
	static final String trustSTOREPASSWD = "abcdef";
	static final String keySTOREPASSWD = "123456";
	static final String ALIASPASSWD = keySTOREPASSWD;
	
	protected Socket socket;
	private BufferedReader inCLA;
	private BufferedReader inVoter;
	private PrintWriter outCLA;
	private PrintWriter outVoter;
	
	static HashMap<String, Integer> VotingResults = new HashMap<String, Integer>();	// <ssn, voterPublicKey>
	static HashMap<String, String> votesByCode = new HashMap<String, String>();		// <valCode, party>
	static String codeIsValid;
	/**
	 * Constructor
	 * @param clientSocket
	 */
    public CTFHandlerThread(Socket clientSocket) {
        this.socket = clientSocket;
	}
    
    public void run()
    {
		try
		{
			inVoter = new BufferedReader( new InputStreamReader( socket.getInputStream() ) );
			outVoter = new PrintWriter( socket.getOutputStream(), true );
			
			String valCode = inVoter.readLine();
			System.out.println("CTF received valCode = " + valCode + " from voter client!");
			
			// Check validation code against CLAServer. TODO: check if voter already has voted
			boolean temp_codeIsValid = validateCodeWithCLA(valCode);	
			boolean alreadyVoted = votesByCode.containsKey(valCode);
			
			int voterCase = (temp_codeIsValid == true ? 1 : 0) + (alreadyVoted == true ? 1 : 0);
			outVoter.println(voterCase);
			
			
			// If the code is valid and has not yet voted
//			if(temp_codeIsValid && !alreadyVoted)
//			{
			if(temp_codeIsValid && alreadyVoted){
				String temp = votesByCode.get(valCode);
				outVoter.println(temp);
			}
				String chosenParty = inVoter.readLine();
				System.out.println("CTF received chosenParty = " + chosenParty + " from voter client!");
				updateAndSaveResult(chosenParty);
				// If the code is valid, but the voter already has voted, 
				// show what that person voted on
				
				// If the code is valid, and the voter hasn't voted, store the chosenparty in votesByCode
				if(temp_codeIsValid && !alreadyVoted)
				{
					votesByCode.put(valCode, chosenParty);
				}
				
				System.out.println("CTF server received validation code " + valCode + " from the voter client");
//			}
//			else // send back the previous results
//			{
//				String chosenParty = inVoter.readLine();
//				updateAndSaveResult(chosenParty);
//			}
			

			outVoter.println(VotingResults.toString());
			socket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
    }
    
    private boolean validateCodeWithCLA(String valCode)
	{
		try
		{
			System.out.println("Starting CLA server connection!");
			
			// Create connection
			InetAddress CLAHost = InetAddress.getLocalHost();
			int CLAPort = DEFAULT_CLA_PORT;
			
			KeyStore ks = KeyStore.getInstance( "JCEKS" );
			ks.load( new FileInputStream( KEYSTORE ), keySTOREPASSWD.toCharArray() );
			
			KeyStore ts = KeyStore.getInstance( "JCEKS" );
			ts.load( new FileInputStream( TRUSTSTORE ), trustSTOREPASSWD.toCharArray() );
			
			KeyManagerFactory kmf = KeyManagerFactory.getInstance( "SunX509" );
			kmf.init( ks, ALIASPASSWD.toCharArray() );
			
			TrustManagerFactory tmf = TrustManagerFactory.getInstance( "SunX509" );
			tmf.init( ts );
			
			SSLContext sslContext = SSLContext.getInstance( "TLS" );
			sslContext.init( kmf.getKeyManagers(), tmf.getTrustManagers(), null );
			SSLSocketFactory sslFact = sslContext.getSocketFactory();      	
			SSLSocket client =  (SSLSocket)sslFact.createSocket(CLAHost, CLAPort);
			client.setEnabledCipherSuites( client.getSupportedCipherSuites() );
			
			System.out.println("\n>>>> CTF <-> CLA SSL/TLS handshake completed");
			
			inCLA = new BufferedReader( new InputStreamReader( client.getInputStream() ) );
			outCLA = new PrintWriter( client.getOutputStream(), true );

			// Send own name to CLA server
			System.out.println("CTF server contacting CLA");
			outCLA.println("CTFServer");
			
			// Send validation code to CLA server for validation
			System.out.println("CTF sending valCode " + valCode + " to CLA!");
			outCLA.println(valCode);
			
			// Read response from CLA server
			codeIsValid = inCLA.readLine();
			System.out.println("CTF received codeIsValid = " + codeIsValid + " from CLA!");
			return Boolean.parseBoolean(codeIsValid);
		}
		catch( Exception x ) {
			System.out.println( x );
			x.printStackTrace();
		}
		return false;
	}
    
    private void updateAndSaveResult(String chosenParty) {
		// kalla på en funktion som läser in en fil med tidigare valresultat.
		BufferedReader br;
		String everything = "";
		try {
			br = new BufferedReader(new FileReader("txt/Results.txt"));
		    StringBuilder sb = new StringBuilder();
		    String line = br.readLine();

		    while (line != null) {
		        sb.append(line);
		        sb.append(System.lineSeparator());
		        line = br.readLine();
		    }
		    everything = sb.toString();
		    br.close();
		} catch (IOException e) {
			//out.println(e.toString());
		}
		
		int resultParty1 = 0;
		int resultParty2 = 0;
		int resultParty3 = 0;
		
		String temp = everything.replace("{","");	//remove character {
		temp = temp.replace("}","");				//remove character }
		temp = temp.replaceAll("\\s","");			//removes white space
		String[] temp2 = temp.split(",");			//split it
		for(int i = 0; i<temp2.length;++i){
			String[] tmp = temp2[i].split("=");		//split it again
			if(tmp[0].equals("Party1")){
				resultParty1 = Integer.parseInt(tmp[1]);
			} else if(tmp[0].equals("Party2")){
				resultParty2 = Integer.parseInt(tmp[1]);
			} else if(tmp[0].equals("Party3")){
				resultParty3 = Integer.parseInt(tmp[1]);
			} else {
				System.out.println("==="+ tmp[0] + "===");
			}
		}
		if(chosenParty.equals("Party1")){
			resultParty1++;
		} else if(chosenParty.equals("Party2")){
			resultParty2++;
		} else if(chosenParty.equals("Party3")){
			resultParty3++;
		} else {
			System.out.println("CTF, updateAndSaveResults - Chosen party is unknown");
		}
		
		VotingResults.put("Party1", resultParty1);
		VotingResults.put("Party2", resultParty2);
		VotingResults.put("Party3", resultParty3);
		
		// uppdatera denna med att öka på med 1 för valt parti
		// TODO: Store voter in order to check for 'already voted' and 'made vote'.
		saveVotingResults(VotingResults);
	}

	private void saveVotingResults(HashMap<String, Integer> votingResults2) {
		File file = new File("txt/Results.txt");
		BufferedWriter writer;
		try {
			writer = new BufferedWriter(new FileWriter(file));
			writer.write(VotingResults.toString());
			writer.close();
		} catch (IOException e) {
			
		}
	}    
}
