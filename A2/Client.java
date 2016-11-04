import java.io.*;
import java.net.*;
import javax.crypto.spec.*;
import java.security.*;
import javax.crypto.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;

/**
 * Client program.  Connects to the server and sends text accross.
 */

public class Client 
{
    private Socket sock;  //Socket to communicate with.
    public static boolean debugOn = false;
	
    /**
     * Main method, starts the client.
     * @param args args[0] needs to be a hostname, args[1] a port number.
     */
    public static void main (String [] args)
    {
	if (args.length != 2) {
		if (!args[2].equals("debug")) {
			System.out.println ("Usage: java Client hostname port#");
		    System.out.println ("hostname is a string identifying your server");
		    System.out.println ("port is a positive integer identifying the port to connect to the server");
		    return;
		}else{
			debugOn = true;	
		}
	}

	try {
	    Client c = new Client (args[0], Integer.parseInt(args[1]), debugOn);
	}
	catch (NumberFormatException e) {
	    System.out.println ("Usage: java Client hostname port#");
	    System.out.println ("Second argument was not a port number");
	    return;
	}
    }
	
    /**
     * Constructor, in this case does everything.
     * @param ipaddress The hostname to connect to.
     * @param port The port to connect to.
     */
    public Client (String ipaddress, int port, Boolean debugOn)
    {
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			BufferedReader serverInput = null;	
			PrintWriter out;
			DataOutputStream sendCipher;
			FileInputStream in_file;
			byte[] ciphertext;
			String stdIn_destination = null;
			String stdIn_Source = null;
			String stdIn_Seed = null;
			int read_bytes;
			int read_bytes2;
			byte[] msg;
			byte[] msg2;
			String serverResponse = "";

			
		/* Try to connect to the specified host on the specified port. */
		try {
		    sock = new Socket (InetAddress.getByName(ipaddress), port);
		}
		catch (UnknownHostException e) {
		    System.out.println ("Usage: java Client hostname port#");
		    System.out.println ("First argument is not a valid hostname");
		    return;
		}
		catch (IOException e) {
		    System.out.println ("Could not connect to " + ipaddress + ".");
		    return;
		}
			
		/* Status info */
		System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);
			
		try {
		    out = new PrintWriter(sock.getOutputStream());
		    sendCipher = new DataOutputStream(new BufferedOutputStream(sock.getOutputStream()));
		    serverInput = new BufferedReader (new InputStreamReader(sock.getInputStream()));
		}
		catch (IOException e) {
		    System.out.println ("Could not create output stream.");
		    return;
		}
			
		try{

			/*The destination file name, length of the source file in bytes, and the source file
		    contents (encrypted and integrity-protected) should then be transferred to the server.*/
		    //Whenenver doing a protocol. Do a debug check and echo it
			System.out.print("Please enter your seed: ");
			stdIn_Seed = stdIn.readLine();
			
			System.out.print("Please enter your source file: ");
			stdIn_Source = stdIn.readLine();
			
			System.out.print("Please enter your destination file: ");
			stdIn_destination = stdIn.readLine();
			
			if(debugOn == true){
		    	System.out.println("Client: Starting to Read Input File Recieved from Client");
		    }
			//start reading the user source file:
			in_file = new FileInputStream(stdIn_Source);
			msg = new byte[in_file.available()];		
			read_bytes = in_file.read(msg);	

			msg2 = stdIn_destination.getBytes("US-ASCII");
			int l = msg2.length;
			//Assumption Length of destination file is somehow shared? No...

			System.out.println("Destination name length: "+l);
			System.out.println("Source file length: "+ msg.length);

			if(debugOn == true){
		    	System.out.println("Client: Encrypting the File Recieved from Client, Sending to Server");
		    }
			//encrypt file with AES
			SecretKeySpec sec_key_spec = CryptoUtilities.key_from_seed(stdIn_Seed.getBytes());
			
			byte[] sizeofSource = new byte[1];
			String sizeofSourceInString = Integer.toString(msg.length);
			sizeofSource = sizeofSourceInString.getBytes("US-ASCII");
			//destination file and  source file contents
			//msg = destination name
			//msg = original source message
			//source file size
			//Destination name first, source second.
			byte[] destSize = new byte[msg2.length + msg.length + sizeofSource.length];
			System.arraycopy(msg2, 0, destSize, 0, msg2.length);
			System.arraycopy(msg, 0, destSize, msg2.length, msg.length);
			System.arraycopy(sizeofSource, 0 ,destSize, (msg2.length + msg.length), sizeofSource.length);

			//Create MAC via HMAC SHA1
			byte[] md; 
			md = CryptoUtilities.append_hash(destSize, sec_key_spec);
					
			//encrypt
			ciphertext = CryptoUtilities.encrypt(md,sec_key_spec);


			//write to stream
			sendCipher.writeInt(ciphertext.length);
			sendCipher.write(ciphertext);
			sendCipher.flush();

			if(debugOn == true){
		    	System.out.println("Client: Waiting to Get Acknowledgment from Server");
		    }
		    serverResponse = serverInput.readLine();
		    if(serverResponse.equals("Message Verified.")){
		    	System.out.println("File has been recieved without any modification.");
		    	System.out.println("Shutting client.");
			    out.close();
			    stdIn.close();
			    sendCipher.close();
			    serverInput.close();
		    }else{
		    	System.out.println("File has been modified!");
		    	System.out.println("Shutting client.");
			    out.close();
			    stdIn.close();
			    sendCipher.close();
			    serverInput.close();
		    }

	    }catch(Exception e){
	    	System.out.println(e);
	    }
	}
}
