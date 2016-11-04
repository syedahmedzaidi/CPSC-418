/*Syed Ahmed Hassan Zaidi
Readme.txt
CPSC 418
10150285*/

Files Submitted:

	1) Client.java - most of the code
	2) Server.java - only debug code added.
	3) ServerThread.java - most of the code
	4) CryptoUtilities.java - untouched/Copy of file provided by the Prof.
	5) source (editable) - used for testing purposes.
	6) destination (editable) - used for testing purposes.

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
	3) Continue to work on Client's instance, and provide seed.
	4) For source: type in Source. The program works specifically for file name source as I had problems trying to implement it abstractly.
	5) For destination: type in Destination. The program works specifically for file name source as I had problems trying to implement it abstractly.
	6) The file will be encrypted and sent to the server. It will wait for response from Server. If debug mode is on, then you will see the screen tell you
		about the process.
	7) Go to Server's instance, and type in the same seed.
	8) File will be checked then decrypted. If you are in debug mode, you will see the process.
	9) An acknowledgement will be sent to the Client who was waiting. 
	10) On the Client screen, you will see if it was verified or unverified.

Solution:
	A solution has been crafted as per the precieved requirements of the question. No additional effort has been put in.

Assumptions: 
	The user always provides the same file name, "source" and "destination". There was some confusion about how the message sent to the server consisting of
	destination name, content, and content size will be decomposed given that no other information is shared. For that specific reason I hard coded in destination
	file name which will always be "destination" (11).
	 		
Client.java:
	If Client is run with a debug mode, a boolean flag is set to true and protocol messages that talk to server are echoed.Client feeds in a seed which will be used 
	to generate a key via the method provided in CryptoUtilities.java. The user then enters in source file, destination file. The source file contents are parsed and 
	read using FileInputStream. A key is generated and a message is crafted using Arraycopy. The syntax is : destination name + source file contents + source file size.
	A hash is computed of the message (destination name+source contents+size). TheHash is appended with the message. And encryped (EK(M+H)). It is then sent to socket's
	and wait for an acknowledgment from server. Once an acknowledgement is recieved, it prints accordingly.
	
ServerThread.java:
	If Server is run with a debug mode, a boolean flag is set to true and protocol messages are echoed. THe server first asks user for same seed and reads from its socket 
	and reads data (the encrypted file). A key is generated from provided seed and then the file is decrypted. The decrypted file's digest is verified using CryptoUtilities
	verify_hash method. A response is sent to Client accordingly. If verified, It proceeds to write to file using CryptoUtilities.java and ArrayCopy to break message apart.

Server.java:
	Almost untouched. Everthing is the same except for debug option. If argument is not 1 (i.e has debug incommand) then check to see if the argument is "debug". If it is then
	set debug boolean value on via static method, debugFlagOn.

CryptoUtilities.java:
	Untouched!