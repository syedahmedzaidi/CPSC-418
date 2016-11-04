/*Syed Ahmed Hassan Zaidi
secureFile.java
CPSC 418
10150285*/
import java.util.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;

public class secureFile{

	private static KeyGenerator key_gen = null;
	private static SecretKey sec_key = null;
	private static byte[] raw = null;
	private static SecretKeySpec sec_key_spec = null;
	private static Cipher sec_cipher = null;
	private static SecureRandom secRan = null;
	
	public static void main(String args[]) throws Exception{
		FileInputStream in_file = null;
		int read_bytes = 0;
		
		try{
			//open files and create them
			in_file = new FileInputStream(args[0]);

			File newFile = new File("ciphertext.txt");
			if(newFile.exists())
				System.out.println("File by the name Ciphertext.txt already exist. You probably do not want to overwrite it.");
			else{
				newFile.createNewFile();
				byte[] seed = args[1].getBytes();
						
				//read file into a byte array
				byte[] msg = new byte[in_file.available()];
				read_bytes = in_file.read(msg);

				//encrypt file with AES
				//key setup - generate 128 bit key using SHA1 and seed.
				key_gen = KeyGenerator.getInstance("AES");
				secRan = SecureRandom.getInstance("SHA1PRNG");
				secRan.setSeed(seed);
				key_gen.init(128, secRan);
				sec_key = key_gen.generateKey();
			
				//Create message digest using MessageDigest (https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html)
				byte[] md; 
				MessageDigest tc1 = MessageDigest.getInstance("SHA1");
				md = tc1.digest(msg);

				//concatenate file with message digest (algorithm from: http://stackoverflow.com/questions/5513152/easy-way-to-concatenate-two-byte-arrays)
				byte[] file_md = new byte[msg.length + md.length];
				//copy original message into empty array file_md
				System.arraycopy(msg, 0, file_md, 0, msg.length);
				//start copying message digest at the end of original message in file_md
				System.arraycopy(md, 0, file_md, msg.length, md.length);
			
				// IV(initiliazation vector) for CBC-MAC encryption
				byte[] initVector = new byte[16];
			
				//get key material in raw form
				raw = sec_key.getEncoded();
				sec_key_spec = new SecretKeySpec(raw, "AES");
			
				//create the cipher object that using transformation form algorithm, mode, padding
				sec_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			
				//do encryption on the file_md and stores it into returningBytes
				byte[] ciphertext = null;
				sec_cipher.init(Cipher.ENCRYPT_MODE, sec_key_spec, new IvParameterSpec(initVector));
				ciphertext = sec_cipher.doFinal(file_md);
				
			
				//writes the result back into file
				FileOutputStream stream = new FileOutputStream(newFile);
				stream.write(ciphertext);
				stream.close();
				System.out.println("Encrypted.");
			}
		}
		catch(Exception e){
			System.out.println(e);
		}
	}
}