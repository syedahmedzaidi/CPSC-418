import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.*;
/**
 * Thread to deal with clients who connect to Server.  Put what you want the
 * thread to do in it's run() method.
 */

public class ServerThread extends Thread
{
    private Socket sock;  //The socket it communicates with the client on.
    private Server parent;  //Reference to Server object for message passing.
    private int idnum;  //The client's id number.
    // HMAC-SHA1 digest length (in bytes)
    private final int HMAC_SHA1_LEN = 20;
	
    /**
     * Constructor, does the usual stuff.
     * @param s Communication Socket.
     * @param p Reference to parent thread.
     * @param id ID Number.
     */
    public ServerThread (Socket s, Server p, int id)
    {
		parent = p;
		sock = s;
		idnum = id;
    }
	
    /**
     * Getter for id number.
     * @return ID Number
     */
    public int getID ()
    {
		return idnum;
    }
	
    /**
     * Getter for the socket, this way the parent thread can
     * access the socket and close it, causing the thread to
     * stop blocking on IO operations and see that the server's
     * shutdown flag is true and terminate.
     * @return The Socket.
     */
    public Socket getSocket ()
    {
		return sock;
    }
	
    /**
     * This is what the thread does as it executes.  Listens on the socket
     * for incoming data and then echos it to the screen.  A client can also
     * ask to be disconnected with "exit" or to shutdown the server with "die".
     */

    public void run ()
    {
		BufferedReader in;
		BufferedReader stdIn;
		PrintWriter out;
		DataInputStream sendCipher = null;
		FileOutputStream stream = null;
		String stdIn_Seed = null;
		String destinationFile = null;
		byte[] incom = null;
		SecretKeySpec sec_key_spec = null;
		byte[] decryptText = null;
		boolean debugOn = false;
		
		try{
			stdIn = new BufferedReader(new InputStreamReader(System.in));
		    in = new BufferedReader (new InputStreamReader (sock.getInputStream()));
			out = new PrintWriter(new OutputStreamWriter(sock.getOutputStream()));
			sendCipher = new DataInputStream(new BufferedInputStream(sock.getInputStream()));
			debugOn = parent.getDebugFlag();
		}
		catch (UnknownHostException e) {
		    System.out.println ("Unknown host error.");
		    return;
		}
		catch (IOException e) {
		    System.out.println ("Could not establish communication.");
		    return;
		}
			
		/* Try to read from the socket */
		try{
		    System.out.print("Please enter seed for key: ");
			stdIn_Seed = stdIn.readLine();

			if(debugOn == true){
		    	System.out.println("Server: Starting File Transfer from Client " +getID());
		    }
			int size = sendCipher.readInt();
			incom = new byte[size];

			sendCipher.readFully(incom);
			sec_key_spec = CryptoUtilities.key_from_seed(stdIn_Seed.getBytes());

			//do decryption on the ciphered text and store it into decryptText
			decryptText = CryptoUtilities.decrypt(incom, sec_key_spec);
			
			if(debugOn == true){
		    	System.out.println("Server: Integrity Check for File Recieved from Client " +getID());
		    }
		    if (CryptoUtilities.verify_hash(decryptText,sec_key_spec)){

				System.out.println("Message digest OK");
				if(debugOn == true){
		    		System.out.println("Server: Sending Acknowledgement to Client " +getID());
		   		}
		   		out.println("Message Verified.");
				out.flush();

		   		byte[] withoutHash = CryptoUtilities.extract_message(decryptText);
			    //11 long always!
			    byte[] destination = Arrays.copyOfRange(withoutHash,0, 11); //we are using the fact that it will always be "destination" no other file.
			    destinationFile = new String(destination, 0, 11, "US-ASCII");
			    //System.out.println(destinationFile);

			    byte[] content = Arrays.copyOfRange(withoutHash, destination.length, withoutHash.length-2);
			    String sourceContent = null;
			    sourceContent = new String( content, 0, content.length, "US-ASCII");
			    //System.out.println(sourceContent);

			    if(debugOn == true){
			    	System.out.println("Server: Writing File Recieved from Client "+getID()+" to File: " +destinationFile);
			    }
			    //search for the file and save it in it
			    stream = new FileOutputStream(destinationFile);
				stream.write(content);
				stream.close();
				out.close();
				sendCipher.close();
				 if(debugOn == true){
			    	System.out.println("Server: File Recieved from Client "+getID()+" has been written to File: " +destinationFile);
			    }	
			}
		    else {
				System.out.println("Error! Invalid message digest!");
				if(debugOn == true){
		    		System.out.println("Server: Sending Acknowledgement to Client " +getID());
		   		}
				out.println("Message Unverified.");
				out.flush();
				out.close();
				sendCipher.close();
		    }
		   
		}catch(Exception e){
			System.out.println(e);
		}
    }
}

