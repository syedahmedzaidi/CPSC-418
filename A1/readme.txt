/*Syed Ahmed Hassan Zaidi
Readme.txt
CPSC 418
10150285*/

Files Submitted:

	1) secureFile.java
	2) decryptFile.java
	3) plaintext.txt (editable) - used for testing purposes.

secureFile.java:

	This is the program which encrypts the file that you provide to it in the command line along with a seed.
	How to:
		In the command line, the user writes "java secureFile plaintext.txt 17561"; this will encrypt the 
		plaintext.txt file with the seed 17561, and a new file ciphertext.txt is created.
	Algorithm:
		The algorithm is based heavily on demo.java which was provided along with the assignment. A 128 bit 
		key is created along with the seed using SHA1-PRNG. For the encryption itself, A message digest is
		generated. The message digest is then appended to the original message, and a new message is created
		called file_md. We then encrypt file_md using AES/CBC/PKCS5Padding which essentialy encrypts using cbc 
		mode of operation with encrption algorithm as AES and the padding scheme PKCS5. Once encrypted, the file
		is written and closed.
	Test:
		Tested with plaintext.txt but can be tested with other txt files. JPEG and ZIP were basically JPEG and ZIP
		of txt file. Once decrypted did give original txt file contents.
decryptFile.java:

	This is the program which decrypts the file that you provide to it in the command line along with a seed.
	How to:
		In the command line, the user writes "java decryptFile ciphertext.txt 17561"; this will encrypt the 
		plaintext.txt file with the seed 17561, and a new file decryptedtext.txt is created.
	Algorithm:
		The algorithm is based heavily on demo.java and first half is similar as secureFile.java 
		which was provided along with the assignment. A 128 bit key is created along with the seed using 
		SHA1-PRNG which will be used in decryption. Following the key generation, the decryption is done
		to return to us the decrypted message. However we check for message digest and compare it with digest
		which we generate. We take the message+digest and set a counter which marks position in the array (digestPos).
		We take the decryptedText length and subtract it by 20 because 20 bytes from the blocking pool of OS are 
		used in the PRNG. We now know the starting position of digest. We copy them in two arrays. We computer our
		own message digest using the decrypted message only (note: without the message digest). We compare if 
		the message digest are equal. If they are we write the decryped message to file called decryptedText.txt.
		If digests are not equal, thus the file has been modified. 
	Test:
		Tested with ciphertext.txt generated from plaintext.txt but can be tested with other txt files. 
		JPEG and ZIP were basically JPEG and ZIP of txt file. Once decrypted did give original txt file contents.