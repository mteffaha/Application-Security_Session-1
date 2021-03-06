package com.polytech.security;



import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.net.URL;
import java.security.*;
import java.util.*;

public class SqueletonTripleDES{

	private static final int KEYS_COUNT = 3;

	static public void main(String[] argv){


		Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
		Security.addProvider(prov);
		
		try{
	
			if(argv.length>0){
				// Create a TripleDES object 
				SqueletonTripleDES the3DES = new SqueletonTripleDES();
			
				if(argv[0].compareTo("-ECB")==0){
					// EBC mode
				  	// encrypt EBC mode
				  	Vector Parameters= 
					  	the3DES.encryptECB(
					  			new FileInputStream(new File(argv[1])),  	// clear text file 
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
				   	  			"DES/ECB/NoPadding"); 						// CipherName 
				  	// decrypt EBC mode
				  	the3DES.decryptECB(Parameters,				 			// the 3 DES keys
				  				new FileInputStream(new File(argv[2])),  	// the encrypted file 
				   	  			new FileOutputStream(new File(argv[3])),	// the decrypted file
				   	  			"DES/ECB/NoPadding"); 		  				// CipherName
				}	
				else if(argv[0].compareTo("-CBC")==0){
					// decryption
				  	// encrypt CBC mode
				  	Vector Parameters = 
					  	the3DES.encryptCBC(
					  			new FileInputStream(new File(argv[1])),  	// clear text file 
				   	  			new FileOutputStream(new File(argv[2])), 	// file encrypted
				   	  			"DES", 										// KeyGeneratorName
					  			"DES/CBC/NoPadding"); 						// CipherName
				   	  			//"DES/CBC/PKCS5Padding"); 					// CipherName 
				  	// decrypt CBC mode	
				  	the3DES.decryptCBC(
				  				Parameters,				 					// the 3 DES keys
			  					new FileInputStream(new File(argv[2])),  	// the encrypted file 
			  					new FileOutputStream(new File(argv[3])),	// the decrypted file
				  				"DES/CBC/NoPadding"); 						// CipherName			
				  				//"DES/CBC/PKCS5Padding"); 		  			// CipherName	  
				}
			
			}
			
			else{
				System.out.println("java TripleDES -EBC clearTextFile EncryptedFile DecryptedFile");
				System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
			} 
		}catch(Exception e){
			e.printStackTrace();
			System.out.println("java TripleDES -EBC clearTextFile EncryptedFile DecryptedFile");
			System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
		}
	}

	
	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptECB(FileInputStream in, 
							FileOutputStream out, 
							String KeyGeneratorInstanceName, 
							String CipherInstanceName){
		try{
			Vector<SecretKey> keys = new Vector<SecretKey>();
			Vector<Cipher> ciphers = new Vector<Cipher>();
		
			// GENERATE 3 DES KEYS
			KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyGeneratorInstanceName);

			for(int i=0;i< KEYS_COUNT;i++){
				keys.add(keyGenerator.generateKey());

			}

			storeKey(keys.get(0),"ebc/DESKey1");
			storeKey(keys.get(1),"ebc/DESKey2");
			storeKey(keys.get(2),"ebc/DESKey3");

			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR ENCRYPTION 
				// WITH THE FIRST GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(0).init(Cipher.ENCRYPT_MODE,keys.get(0));
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION
				// WITH THE SECOND GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(1).init(Cipher.DECRYPT_MODE,keys.get(1));
			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName 
				// FOR ENCRYPTION
				// WITH THE THIRD GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(2).init(Cipher.ENCRYPT_MODE,keys.get(2));


			// GET THE MESSAGE TO BE ENCRYPTED FROM N , plus add Zero paddings
			byte inData[] = new byte[in.available()+(8-(in.available()%8))];
			in.read(inData);
			// CIPHERING     
				// CIPHER WITH THE FIRST KEY
				byte[] ciphered = ciphers.get(0).doFinal(inData);
				// DECIPHER WITH THE SECOND KEY
				byte[] deciphered = ciphers.get(1).doFinal(ciphered);
				// CIPHER WITH THE THIRD KEY
				ciphered = ciphers.get(2).doFinal(deciphered);
				// write encrypted file


			// WRITE THE ENCRYPTED DATA IN OUT
			out.write(ciphered);
			// return the DES keys list generated		
			return keys;
			
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	 * 3DES ECB Decryption 
	 */
	private void decryptECB(Vector Parameters, 
						FileInputStream in, 
						FileOutputStream out, 
						String CipherInstanceName){
		try{
			Vector<Cipher> ciphers = new Vector<Cipher>();

			// CREATE A DES CIPHER OBJECT 
				// WITH CipherInstanceName
				// FOR DECRYPTION 
				// WITH THE THIRD GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(0).init(Cipher.DECRYPT_MODE, (Key) Parameters.get(0));
			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE SECOND GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(1).init(Cipher.ENCRYPT_MODE, (Key) Parameters.get(1));
			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE THIRD GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(2).init(Cipher.DECRYPT_MODE, (Key) Parameters.get(2));
			
			// GET THE ENCRYPTED DATA FROM IN
			byte inData[] = new byte[in.available()];
			in.read(inData);
			// DECIPHERING     
				// DECIPHER WITH THE THIRD KEY
			byte[] deciphered = ciphers.get(2).doFinal(inData);
				// 	CIPHER WITH THE SECOND KEY
			byte[] ciphered = ciphers.get(1).doFinal(deciphered);
				// 	DECIPHER WITH THE FIRST KEY
			deciphered = ciphers.get(0).doFinal(ciphered);

			// WRITE THE DECRYPTED DATA IN OUT
			out.write(deciphered);
		}catch(Exception e){
			e.printStackTrace();
		}

	}
	  
	/**
	 * 3DES ECB Encryption
	 */
	private Vector encryptCBC(FileInputStream in, 
							FileOutputStream out, 
							String KeyGeneratorInstanceName, 
							String CipherInstanceName){
		try{

			Vector<Object> keys = new Vector<Object>();
			Vector<Cipher> ciphers = new Vector<Cipher>();

			// GENERATE 3 DES KEYS
			KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyGeneratorInstanceName);

			for(int i=0;i< KEYS_COUNT;i++){
				keys.add(keyGenerator.generateKey());

			}



			SecureRandom random = new SecureRandom();
			byte iv[] = new byte[8];
			random.nextBytes(iv);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);

			keys.add(ivSpec);

			storeKey((Key) keys.get(0),"cbc/DESKey1");
			storeKey((Key) keys.get(1),"cbc/DESKey2");
			storeKey((Key) keys.get(2),"cbc/DESKey3");


			FileOutputStream outIv = new FileOutputStream("cbc/IvSpec");
			outIv.write(ivSpec.getIV());
			//Close the output stream
			outIv.close();


			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE FIRST GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(0).init(Cipher.ENCRYPT_MODE, (Key) keys.get(0), ivSpec);
			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE SECOND GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(1).init(Cipher.DECRYPT_MODE, (Key) keys.get(1),ivSpec);
			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE THIRD GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(2).init(Cipher.ENCRYPT_MODE, (Key) keys.get(2),ivSpec);


			// GET THE MESSAGE TO BE ENCRYPTED FROM N
			byte inData[] = new byte[in.available()+(8-(in.available()%8))];
			in.read(inData);
			// CIPHERING
			// CIPHER WITH THE FIRST KEY
			byte[] ciphered = ciphers.get(0).doFinal(inData);
			// DECIPHER WITH THE SECOND KEY
			byte[] deciphered = ciphers.get(1).doFinal(ciphered);
			// CIPHER WITH THE THIRD KEY
			ciphered = ciphers.get(2).doFinal(deciphered);
			// write encrypted file


			// WRITE THE ENCRYPTED DATA IN OUT
			out.write(ciphered);
			// return the DES keys list generated
			return keys;
			
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	/**
	 * 3DES ECB Decryption 
	 */
	private void decryptCBC(Vector Parameters, 
						FileInputStream in, 
						FileOutputStream out, 
						String CipherInstanceName){
		try{

			Vector<Cipher> ciphers = new Vector<Cipher>();

			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE THIRD GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(0).init(Cipher.DECRYPT_MODE, (Key) Parameters.get(0),(IvParameterSpec)Parameters.get(3));
			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR DECRYPTION
			// WITH THE SECOND GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(1).init(Cipher.ENCRYPT_MODE, (Key) Parameters.get(1),(IvParameterSpec)Parameters.get(3));
			// CREATE A DES CIPHER OBJECT
			// WITH CipherInstanceName
			// FOR ENCRYPTION
			// WITH THE THIRD GENERATED DES KEY
			ciphers.add(Cipher.getInstance(CipherInstanceName));
			ciphers.get(2).init(Cipher.DECRYPT_MODE, (Key) Parameters.get(2),(IvParameterSpec)Parameters.get(3));

			// GET THE ENCRYPTED DATA FROM IN
			byte inData[] = new byte[in.available()];
			in.read(inData);
			// DECIPHERING
			// DECIPHER WITH THE THIRD KEY
			byte[] deciphered = ciphers.get(2).doFinal(inData);
			// 	CIPHER WITH THE SECOND KEY
			byte[] ciphered = ciphers.get(1).doFinal(deciphered);
			// 	DECIPHER WITH THE FIRST KEY
			deciphered = ciphers.get(0).doFinal(ciphered);

			// WRITE THE DECRYPTED DATA IN OUT
			out.write(deciphered);
			
		}catch(Exception e){
			e.printStackTrace();
		}

	}

	private void storeKey(Key key,String filename) throws IOException {
		FileWriter fstream = new FileWriter(filename);
		BufferedWriter out = new BufferedWriter(fstream);
		out.write(Base64.getEncoder().encodeToString(key.getEncoded()));
		//Close the output stream
		out.close();
	}


	private SecretKey readKey(String filename,String KeyGeneratorInstanceName) throws IOException {
		/*

		 */
		String encodedKey;
		BufferedReader br = new BufferedReader(new FileReader(filename));
		try {
			StringBuilder sb = new StringBuilder();
			String line = br.readLine();

			while (line != null) {
				sb.append(line);
				sb.append(System.lineSeparator());
				line = br.readLine();
			}
			encodedKey = sb.toString();
		} finally {
			br.close();
		}
		byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
		return new SecretKeySpec(decodedKey, 0, decodedKey.length, KeyGeneratorInstanceName);
	}


	  

}