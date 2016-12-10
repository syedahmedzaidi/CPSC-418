/*Syed Ahmed Hassan Zaidi
README.txt
CPSC 418
10150285*/

Files Submitted:

	1) RSATool.java


How to compile:
	Open cmd, browse to directory where the program is stored. Type in "javac *.java" to compile all the
	files in one go.

Tested:
	Tested on cpsc.linux.ucalgary.ca

How to run:
	Open two instances of cmd from the directory where the files are stored. Follow the following steps:
	1) In one instance, type in "java Server XXXX" or "java Server XXXX debug" to run in debug mode. XXXX refers to port number and must be 4 digits long.
	2) In the second instance (seperate), type in "java Client Y.Y.Y.Y XXXX" or "java Client Y.Y.Y.Y XXXX debug" to run in debug mode. The value Y.Y.Y.Y
		is listed on the Server's cmd instance and so is the XXXX (port #).
	3) The Server side generates the RSA private keys and sends the public keys to the client
	4) The client recieves the public key, encrypts the AES key and sends it to the server
	5) The server Decrypts the AES using the private key (d).
	6) File transfer is started
	7) type in : input for input file
	8) type in: output for output file
	9) Vola, everything works like Assignment 3.

Solution:
	A solution has been crafted as per the requirements of the question. RSA-OAEP encryption was implemented as per the slides.
	The decryption algorithm was written with inclusion of Chinese Remainder theorem as defined in assignment4.pdf and RSA-OAEP decryption
	algorithm as stated in the slides. Extended Euclidean Algorithm was also implemented and was "borrowed" from the internet. The code was
	taken from here -> https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/pqc/math/ntru/euclid/BigIntEuclidean.java

Bugs:
	This is the part that had me scratching my head for a while. I had emailed Sebastian but did not get any response. The bug was
	BadPaddingException. I had discussed it with multiple students who also had the same problem. Everyone had to offer a different
	explaination about why this was happening. Some believed that it was due to negative AES key (the value of AES key is negative)
	and when converted to BigInteger, it did not retain its value or something which lead to this error. Others believed it was due to
	the BigInteger in encrypt function being xor'd and making the first bit 1 thus making it negative and through the magic of computer
	sciences it leads to BadPaddingException. As you can see, I did not understand what both of them were saying and why it is happening.
	I tried both fixes put forward by the students, as shown in the code. Line 281-285 is one fix which basically checks if the BigInteger
	is negative, if so then just call the function again and do all the operations once again. This "fixed", or they claim so, the BadPaddingException.
	Other said make sure that in Client.java file's getKey method, make sure you are generating a positive value. I did so by putting the
	KeyGenerator block within a do while loop and checking if the first bit is 1 or 0 and only breaking from the while loop if the bit is
	0 thus an even number. This also did not fix the error for me. The nature of BadPaddingException is such that the two AES keys, the
	one generated on Client side, and the one decrypted on the Server side are not the same. Only when this case happens, then there is a
	BadPaddingException. However, this happens sometimes and there are times where on the Server side the AES key is decrypted perfectly and
	does not lead to a BadPaddingException.

RSATool:
	- RSATool(BigInteger new_n, BigInteger new_e, boolean setDebug):
				Set new_n, new_e and debug status to RSATool's counter parts. It is called in the Client's getKey method where the AES key is encrypted using
				the (n,e) recieved from the Server. It makes sure that public key (n,e) is used to encrypt the key recieved from the server.
	- RSATool(boolean setDebug):
		Initial setup of key generation. Two distinct large prime numbers 'p' & 'q' are generated first. Sophie Germain method from assignment 3 is employed,
		With in a do while loop 'p' & 'q' (BigIntegers) are generated at random using SecureRandom such that they are "probablePrime". Then they are checked
		employing the method that 'test_p' and 'test_q' (2p+1 and 2q+1, respectively) and p should both be probablePrime with Certainity value 3. 'N' is then computed
		as per the formula (n=pq). I then compute the phi(n) which is (p-1)(q-1). Phi(n) is computed because we need it to compute 'e'. 'e' is computed such that gcd
		of e and phi(n) has to equal to 0. This is accomplished using a while loop where i generate a random BigInteger e such that it's gcd with phi(N) is NOT equal to
		1. Once it is one, i break from the loop and the last stored value is such that gcd of random e and phi(n) is equal to 1. Following that BigInteger d is computed
		such that e modInverse (function) phi(n).
	- encrypt(byte[] plaintext):
		RSA-OAEP encryption Followed as per Week 10 Slides: page 40/45.
	- decrypt(byte[] ciphertext):
			Followed as per Chinese Remainder theorem as per assignment4.pdf description and RSA-OAEP decryption is implemented as per Week 10 Slides: page 41/45.
