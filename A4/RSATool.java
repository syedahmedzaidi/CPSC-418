import java.io.*;
import java.util.Arrays;
import java.math.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * This class provides an implementation of 1024-bit RSA-OAEP.
 *
 * @author Syed Ahmed Zaidi, Skeleton Provided by: Mike Jacobson
 * @version 1.0, December 3, 2016
 */
/**
************************Chinese remainder theorem (Problem 2)*******************************
* Step 1: Compute
*   d_p == d (mod p-1), 0 <= dp <= p-2
*   d_q == d (mod q-1), 0 <= dp <= q-2
* Step 2: Compute
*   m_p == C^(d_p) (mod p), 1 <= mp <= p-1
*   m_q == C^(d_q) (mod q), 1 <= mq <= q-1
* Step 3: Use the Extended Euclidean Algorithm to find x and y such that
*   px + qy = 1         (Such integers exist because gcd(p,q) = 1)
* Step 4: Set M == (px)mq + (qy)mp (mod n), 0 <= M <= n-1
************************Chinese remainder theorem (Problem 2)*******************************
*/
public class RSATool {
    // OAEP constants
    private final static int K = 128;   // size of RSA modulus in bytes
    private final static int K0 = 16;  // K0 in bytes
    private final static int K1 = 16;  // K1 in bytes

    // RSA key data
    private BigInteger n;
    private BigInteger e, d, p, q;

    // TODO:  add whatever additional variables that are required to implement
    //    Required variable for Chinese Remainder decryption as described in Problem 2 or above in comments
    private BigInteger phiOfn, d_p, d_q, m_p, m_q;

    // SecureRandom for OAEP and key generation
    private SecureRandom rnd;

    private boolean debug = false;



    /**
     * Utility for printing protocol messages
     * @param s protocol message to be printed
     */
    private void debug(String s) {
	if(debug)
	    System.out.println("Debug RSA: " + s);
    }


    /**
     * G(M) = 1st K-K0 bytes of successive applications of SHA1 to M
     */
    private byte[] G(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}


	byte[] output = new byte[K-K0];
	byte[] input = M;

	int numBytes = 0;
	while (numBytes < K-K0) {
          byte[] hashval = sha1.digest(input);

	  if (numBytes + 20 < K-K0)
	      System.arraycopy(hashval,0,output,numBytes,K0);
	  else
	      System.arraycopy(hashval,0,output,numBytes,K-K0-numBytes);

	  numBytes += 20;
	  input = hashval;
	}

	return output;
    }



    /**
     * H(M) = the 1st K0 bytes of SHA1(M)
     */
    private byte[] H(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}

        byte[] hashval = sha1.digest(M);

	byte[] output = new byte[K0];
	System.arraycopy(hashval,0,output,0,K0);

	return output;
    }



    /**
     * Construct instance for decryption.  Generates both public and private key data.
     *
     * TODO: implement key generation for RSA as per the description in your write-up.
     *   Include whatever extra data is required to implement Chinese Remainder
     *   decryption as described in Problem 2.
     */
    public RSATool(boolean setDebug) {
	// set the debug flag
    	debug = setDebug;

    	rnd = new SecureRandom();

    	// TODO:  include key generation implementation here (remove init of d)
        // n = pq
        // First generate two distinct large primes p and q. Suitable choice is sophie germain
        //compute n and phiOfn = (p-1)(q-1)
        //Select random integer e (element of) Z*phiOfn (So 1 <= e <= phiOfn and gcd(e, phiOfn) = 1)
        //Solve linear congruence de == 1 (mod phiOfn) for d (element of) Z*phiOfn
        // keep d, p , q secret and make n and e public

        p = BigInteger.probablePrime(512, rnd);
        q = BigInteger.probablePrime(512, rnd);
        boolean test_p, test_q;
        //Certainity value 3
       do{
            p = BigInteger.probablePrime(512, rnd);
            test_p = p.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE).isProbablePrime(3);
        } while (!p.isProbablePrime(3) || !test_p);

        do {
            q = BigInteger.probablePrime(512, rnd);
            test_q = q.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE).isProbablePrime(3);
        }while (q.equals(p)|| !q.isProbablePrime(3) || !test_q);

        //compute n
        n = p.multiply(q);

        // computer phiOfn = (p-1)(q-1)
        BigInteger p_1 = p.subtract(BigInteger.ONE);
        BigInteger q_1 = q.subtract(BigInteger.ONE);
        phiOfn = p_1.multiply(q_1);

        //Select a random integer e such that 1 <= e <= phiOfn and gcd(e, phiOfn) = 1
        BigInteger e_1 = new BigInteger(phiOfn.bitCount(), rnd);
        while(!phiOfn.gcd(e_1).equals(BigInteger.ONE)){
            e_1 = new BigInteger(phiOfn.bitCount(), rnd);
        }
        e = e_1;

        //d (element of) Z*phiOfn
        d = e.modInverse(phiOfn);
        //debug purposes
        /*System.out.println("P: " + p);
        System.out.println("Q: "+q);
        System.out.println("N: "+ n);
        System.out.println("Phi of N: "+ phiOfn);
        System.out.println("E: "+ e);
        System.out.println("D: "+ d);*/
    }



    /**
     * Construct instance for encryption, with n and e supplied as parameters.  No
     * key generation is performed - assuming that only a public key is loaded
     * for encryption.
     */
    public RSATool(BigInteger new_n, BigInteger new_e, boolean setDebug) {
	// set the debug flag
	 debug = setDebug;

	// TODO:  initialize RSA decryption variables here
    rnd = new SecureRandom();

    n = new_n;
    e = new_e;

    d = p = q = null;
    }



    public BigInteger get_n() {
	return n;
    }

    public BigInteger get_e() {
	return e;
    }



    /**
     * Encrypts the given byte array using RSA-OAEP.
     *
     * TODO: implement RSA encryption
     *
     * @param plaintext  byte array representing the plaintext
     * @throw IllegalArgumentException if the plaintext is longer than K-K0-K1 bytes
     * @return resulting ciphertext
     */
    public byte[] encrypt(byte[] plaintext) {
	debug("In RSA encrypt");

	// make sure plaintext fits into one block
	//that the input byte arrays convert to integers strictly less than n
	if(new BigInteger(plaintext).compareTo(n) >= 0){
		throw new IllegalArgumentException("plaintext longer than one block");
	}

    // TODO:  implement RSA-OAEP encryption here (replace following return statement)
    //Week 10 Slides: page 40/45

        if (plaintext.length > K-K0-K1)
	    throw new IllegalArgumentException("plaintext longer than one block");

        BigInteger m = get_n();
        //If M = (s||t) >= N, go to 1
        while(m.compareTo(get_n()) >= 0 || m.compareTo(BigInteger.ONE) < 0 ){
            //1) Generate a random k0-bit number r
            BigInteger r = new BigInteger(K, rnd);
            while (r.compareTo(BigInteger.ZERO) <  0 || r.compareTo(n) >= 0) {
				r = new BigInteger(128, rnd);
	    	}

	    	byte[] r_byte_array = r.toByteArray();

            //2) Compute s = (M||0^K1) XOR G(r)
            byte[] g_r = G(r_byte_array);
            byte[] append = new byte[K-K0];
          	//Append 0s to M.
	    	for (int i = 0; i < append.length; i++) {
				if (i < plaintext.length) {
		    		append[i] = plaintext[i];
				} else {
		    		append[i] = 0;
				}
	    	}

            //byte[]  test = new BigInteger(append).xor(new BigInteger(g_r)).toByteArray();
            //how to xor two byte arrays
            //http://stackoverflow.com/questions/24487006/java-xor-byte-array-not-returning-expected-result

            byte[] s = new byte[append.length];
            //int i = 0;
            for (int i = 0; i < s.length; i++) {
                s[i] = (byte) (append[i] ^ g_r[i]);
            }

            //3) compute t = r xor H(s)
            byte[] t = new byte[K0];
            byte[] h = H(s);
            for (int j = 0; j < t.length; j++) {
                t[j] = (byte) (r_byte_array[j] ^ h[j]);
            }

            //4) compute C = (s||t)^e (mod N)
            byte[] c = new byte[s.length + t.length];
            System.arraycopy(s, 0, c, 0, s.length);
            System.arraycopy(t, 0, c, s.length, t.length);

            BigInteger b1 = new BigInteger(c);
            //Asked a fix from Mike from tutorial who suggested the following, but it breaks/works without it too?

            /*if(b1.compareTo(BigInteger.valueOf(0)) == -1){
            	return encrypt(plaintext);
            }*/

            m = new BigInteger(c);

        }

        BigInteger cipher1 = m.modPow(e, n);

        byte[] cipher_byte_array = cipher1.toByteArray();
        //debug("C length: "+cipher_byte_array.length);
        return cipher_byte_array;
    }


    /**
     * Decrypts the given byte array using RSA.
     *
     * TODO:  implement RSA-OAEP decryption using the Chinese Remainder method described in Problem 2
     *
     * @param ciphertext  byte array representing the ciphertext
     * @throw IllegalArgumentException if the ciphertext is not valid
     * @throw IllegalStateException if the class is not initialized for decryption
     * @return resulting plaintexttext
     */
    public byte[] decrypt(byte[] ciphertext) {
	debug("In RSA decrypt");

	BigInteger cipher = new BigInteger(ciphertext);
	//that the input byte arrays convert to integers strictly less than n
    if (cipher.compareTo(n) >= 0) {
        throw new IllegalArgumentException("ciphertext bigger than one block");
    }
	// make sure class is initialized for decryption
	if (d == null)
	    throw new IllegalStateException("RSA class not initialized for decryption");

	// TODO:  implement RSA-OAEP encryption here (replace following return statement)

    //algorithm described at the start of the file.

    //Step 1: Compute d_p == d (mod p-1), 0 <= dp <= p-2
    //		  Compute d_q == d (mod q-1), 0 <= dp <= q-2
    d_p = d.mod(p.subtract(BigInteger.ONE));
    d_q = d.mod(q.subtract(BigInteger.ONE));

    //Step 2: Compute
        //m_p == C^(d_p) (mod p), 1 <= mp <= p-1
        //m_q == C^(d_q) (mod q), 1 <= mq <= q-1
    m_p = cipher.modPow(d_p, p);
    m_q = cipher.modPow(d_q, q);

    //Step 3: Use the Extended Euclidean Algorithm to find x and y such that
    //			px + qy = 1  (Such integers exist because gcd(p,q) = 1)
    //EEA source code borrowed from:
    // https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/pqc/math/ntru/euclid/BigIntEuclidean.java
    BigInteger orig_p = p;
    BigInteger orig_q = q;
	BigInteger x = BigInteger.ZERO;
	BigInteger lastx = BigInteger.ONE;
	BigInteger y = BigInteger.ONE;
	BigInteger lasty = BigInteger.ZERO;

	while (!p.equals(BigInteger.ZERO)) {
	    BigInteger a = q.divide(p);
	    BigInteger b = q.mod(p);
	    BigInteger temp = x.subtract(lastx.multiply(a));
	    BigInteger temp1 = y.subtract(lasty.multiply(a));

	    q = p;
	    p = b;
	    x = lastx;
	    y = lasty;
	    lastx = temp;
	    lasty = temp1;
	}

    //debug purposes
    //System.out.println("Roots  x : "+ x +" y :"+ y);

    //System.out.println("Check for x and y: " + (p.multiply(x)).add(q.multiply(y)) );

    // 4) compute m = px(mq) + qy(mp) (mod n)
    BigInteger pxmq = orig_p.multiply(x.multiply(m_q));
	BigInteger qymp = orig_q.multiply(y.multiply(m_p));
    //via Chinese remainder theorem
    BigInteger m = pxmq.add(qymp).mod(n);

    //unpad the message:

    // Computer (s||t) == C^d(mod n)
    byte[] message_bytes = m.toByteArray();
    //s = k - k0
    byte[] s = Arrays.copyOfRange(message_bytes, 0, K - K0);
	byte[] t = Arrays.copyOfRange(message_bytes, K - K0, message_bytes.length);

    //H(s)
    byte[] h = H(s);

    //r = t xor H(s)
    byte[] r = new byte[K0];
    for (int i = 0; i < r.length; i++) {
        r[i] = (byte) (t[i] ^ h[i]);
    }

    //G(r)
    byte[] g = G(r);

    // (m || 0^K1) = s xor G(r)
    byte[] v = new byte[K-K0];
    for (int i = 0; i < v.length; i++) {
        v[i] = (byte) (s[i] ^ g[i]);
    }

    //m
    byte[] msg_bytes = Arrays.copyOfRange(v, 0, 96);//96

    return msg_bytes;
    }
}
