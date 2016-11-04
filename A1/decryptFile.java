/*Syed Ahmed Hassan Zaidi
decryptFile.java
CPSC 418
10150285*/
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.interfaces.*;
import java.security.interfaces.DSAKey;
import java.math.*;
import java.security.SecureRandom;
import java.util.Base64;

public class decryptFile{
	
	private static KeyGenerator key_gen = null;
	private static KeyGenerator new_key_gen = null;
	private static SecretKey sec_key = null;
	private static byte[] raw = null;
	private static SecretKeySpec sec_key_spec = null;
	private static Cipher sec_cipher = null;
	private static SecureRandom secRan = null;
	
	public static void main(String args[]){
		
		FileInputStream in_file = null;
		FileOutputStream out_file = null;
		
		try{
			//open files
			in_file = new FileInputStream(args[0]);
			File newFile = new File("decryptedtext.txt");
			if(newFile.exists())
				System.out.println("File by the name decryptedtext.txt already exist. You probably do not want to overwrite it.");
			else{
				newFile.createNewFile();
				byte[] seed = args[1].getBytes();
			
				//read file into byte array this will be file we have to decrypt
				byte[] ciphtext = new byte[in_file.available()];
				in_file.read(ciphtext);
			
				//encrypt file with AES
				//key setup - generate 128 bit key using SHA1 and seed.
				key_gen = KeyGenerator.getInstance("AES");
				secRan = SecureRandom.getInstance("SHA1PRNG");
				secRan.setSeed(seed);
				key_gen.init(128, secRan);
				sec_key = key_gen.generateKey();
			
				// IV(initiliazation vector) for CBC-MAC encryption
				byte[] initVector = new byte[16];

				//get key material in raw form
				raw = sec_key.getEncoded();
				sec_key_spec = new SecretKeySpec(raw, "AES");
			
				//create the cipher object that using transformation form algorithm, mode, padding
				sec_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

				//do decryption on the ciphered text and stores it into decryptText
				byte[] decryptText = null;
				sec_cipher.init(Cipher.DECRYPT_MODE, sec_key_spec, new IvParameterSpec(initVector));
				decryptText = sec_cipher.doFinal(ciphtext);

				//split message and digest.
				//get length of message and subtract 20 (SHA-1 digest length in bytes) to get to starting position of digest.
				int digestPos = decryptText.length-20;
				byte[] origMsg = new byte[digestPos];
				byte[] getDigest = new byte[20];
				System.arraycopy(decryptText, 0, origMsg, 0, digestPos);
				System.arraycopy(decryptText, digestPos, getDigest, 0, 20);

				//create comparing digest	
				//Create message digest using MessageDigest (https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html)
				byte[] md; 
				MessageDigest tc1 = MessageDigest.getInstance("SHA1");
				md = tc1.digest(origMsg);
			
				//get encodings to compare digests. base64 encoding is prefered to ensure that digest is not corrupted.
				String origDigest = Base64.getEncoder().encodeToString(getDigest);
				String compareDigest = Base64.getEncoder().encodeToString(md);
	
				if(compareDigest.equals(origDigest) == true){
					FileOutputStream stream = new FileOutputStream(newFile);
					stream.write(origMsg);
					stream.close();
					System.out.println("Decryption complete.");
				}else{
					System.out.println("File has been modified.");
				}
			}
		}
		catch(Exception e){
			System.out.println(e);
		}
	}
}