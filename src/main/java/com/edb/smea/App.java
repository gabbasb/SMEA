package com.edb.smea;

import java.io.*;

import java.math.BigInteger;

import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.KeyFactory;
import java.security.spec.*;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.sql.*;
import java.util.Calendar;
import java.net.URL;
import java.net.URI;
import java.nio.ByteBuffer;


public class App 
{
	private static final String ALGORITHM = "AES";
	private static final String CIPHER = "AES/CBC/PKCS5PADDING";
	private static final String m_url = "jdbc:postgresql://127.0.0.1:5432/test_db";
	private static final String m_user = "postgres";
	private static final String m_password = "abc123";
	
	public static Connection m_pg = null;
	
	public static String bytesToHex(byte[] bytes) {
		StringBuilder sb = new StringBuilder();
		for (byte b : bytes) {
			sb.append(String.format("%02X ", b));
		}
		return sb.toString();
	}

	public static int arrayContains(String[] optionsArray, String optionPassed)
	{
		int size = optionsArray.length;
		for (int i = 0; i < size; i++)
		{
			if (optionsArray[i].equals(optionPassed)) {
				return i;
			}
		}
		return -1;
	}

	public static String getUserInput(String inputMsg) {
		Scanner scanner = new Scanner(System.in);
		System.out.print(inputMsg);
		return scanner.nextLine();
	}

	static String getRandomString(int n) {
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                    + "0123456789"
                                    + "abcdefghijklmnopqrstuvxyz";

        StringBuilder sb = new StringBuilder(n);
        for (int i = 0; i < n; i++) {
            int index = (int)(AlphaNumericString.length() * Math.random());
            sb.append(AlphaNumericString.charAt(index));
        }

        return sb.toString(); 
    }

	public static String encryptMessage(byte[] key, byte[] initVector, String msg) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
		byte[] encrypted = cipher.doFinal(msg.getBytes("UTF-8"));
		String encoded = Base64.getEncoder().encodeToString(encrypted);
		return encoded;
	}

	public static String decryptMessage(byte[] key, byte[] initVector, String encrypted) throws Exception {
		IvParameterSpec iv = new IvParameterSpec(initVector);
		SecretKeySpec skeySpec = new SecretKeySpec(key, ALGORITHM);
		Cipher cipher = Cipher.getInstance(CIPHER);
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
		byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));
		return new String(original);
	}

    public static Certificate generateCertificate(KeyPair keyPair) throws CertificateException, OperatorCreationException {
		X500Name name = new X500Name("cn=For Demo");
		SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
		final Date start = new Date();
		final Date until = Date.from(LocalDate.now().plus(365, ChronoUnit.DAYS).atStartOfDay().toInstant(ZoneOffset.UTC));
		final X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name,
					new BigInteger(10, new SecureRandom()),
									start,
									until,
									name,
									subPubKeyInfo
									);
		ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA").setProvider(new BouncyCastleProvider()).build(keyPair.getPrivate());
		X509CertificateHolder holder = builder.build(signer);

		Certificate cert = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
		return cert;
    }

    static byte[] genKeyPair(String keyFileName) throws NoSuchAlgorithmException, KeyStoreException, FileNotFoundException, IOException, CertificateException, OperatorCreationException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair();

		PublicKey publicKey = kp.getPublic();
		PrivateKey privateKey = kp.getPrivate();

		String keyPwd = getUserInput("Enter your key password (q to quit):");
		if (keyPwd.length() <= 1)
			return "q".getBytes();
		String keyStorePwd = getUserInput("Enter your keystore password (q to quit):");
		if (keyStorePwd.length() <= 1)
			return "q".getBytes();

		Security.addProvider(new BouncyCastleProvider());
		File keyStoreLocation;
		KeyStore keyStore = KeyStore.getInstance("JKS");
		
		keyStoreLocation = new File("/tmp/" + keyFileName + ".jks");
		keyStore.load(null, keyStorePwd.toCharArray());

		System.out.println("Stored keystore to " + keyStoreLocation);

		Certificate wrapped = generateCertificate(kp);
		Entry entry = new PrivateKeyEntry(kp.getPrivate(), new Certificate[]{wrapped});

		keyStore.setEntry(keyFileName, entry, new KeyStore.PasswordProtection(keyPwd.toCharArray()));

		keyStore.store(new FileOutputStream(keyStoreLocation), keyStorePwd.toCharArray());
		return publicKey.getEncoded();
	}

	public static int addUser() {
		String userName;
		byte[] userPublicKey = "".getBytes();
		String SQL = "INSERT INTO smea.tbl_users(u_name, u_public_key) VALUES(?,?)";

		int count = 0;

		try {
			PreparedStatement insUser = m_pg.prepareStatement(SQL);
			count = 0;

			// a) Select a username.
			while (true) {
				userName = getUserInput("Enter your desired username (q to quit):");
				if (userName.length() <= 1) {
					insUser.close();
					return count;
				}

				insUser.setString(1, userName);
				try {
					// b) Select a key password.
					// c) Select a keystore password.
					// d) Generate a public-private key pair.
					// e) Store the key pair in the keystore.
					userPublicKey = genKeyPair(userName);
				} catch (Exception e) {
					e.printStackTrace();
				}
				if (userPublicKey.length <= 1)
					return count;
				insUser.setBytes(2, userPublicKey);

				// f) Insert the new user in the table tbl_users.
				insUser.executeUpdate();
				count++;
			}
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		return count;
	}

	public static String rightPad(String src, int count, char pad) {
		StringBuilder sb = new StringBuilder(src);
		int reqCount = count - src.length();
		for(int i = reqCount; i >= 0; i--) {
			sb.append(pad);
		}
		return sb.toString();
	}

	public static KeyPair loadKeyPair(final File keystoreFile,
									final String keyStorePwd,
									final String keyStoreType,
									final String keyAlias,
									final String keyPwd)
									throws KeyStoreException,
											IOException,
											NoSuchAlgorithmException,
											CertificateException,
											UnrecoverableKeyException
	{
		if (keystoreFile == null) {
			return null;
		}
		final URI keystoreUri = keystoreFile.toURI();
		final URL keystoreUrl = keystoreUri.toURL();
		final KeyStore keystore = KeyStore.getInstance(keyStoreType);
		InputStream ksStream = null;
		try {
			ksStream = keystoreUrl.openStream();
			keystore.load(ksStream, keyStorePwd.toCharArray());
		} finally {
			if (ksStream != null) {
				ksStream.close();
			}
		}
		final PrivateKey privateKey = (PrivateKey)keystore.getKey(keyAlias, keyPwd.toCharArray());

		final Certificate cert = keystore.getCertificate(keyAlias);
		final PublicKey publicKey = cert.getPublicKey();
		KeyPair kp = new KeyPair(publicKey, privateKey);
		return kp;
	}

	public static KeyPair getUserKeyPair(String username) {
		KeyPair userKeyPair = null;

		String keyStorePwd = getUserInput("Enter keystore password (q to quit):");
		if (keyStorePwd.length() <= 1)
			return null;

		String keyPwd = getUserInput("Enter key password (q to quit):");
		if (keyPwd.length() <= 1)
			return null;

		try {
			userKeyPair = loadKeyPair(new File("/tmp/"+ username + ".jks"),
								keyStorePwd, "JKS", username, keyPwd);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return userKeyPair;
	}

	public static int getUserID(String username) {
		int userID = 0;
		try {
			Statement st = m_pg.createStatement();
			ResultSet rs = st.executeQuery("SELECT u_id FROM smea.tbl_users WHERE u_name = '" + username + "';");
			while (rs.next())
			{
				userID = rs.getInt(1);
			}
			rs.close();
			st.close();
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		return userID;
	}

	public static int addFriend() {
		// a) Enter username.
		String username = getUserInput("Enter your username (q to quit):");
		if (username.length() <= 1)
			return 0;

		// d) Confirm username exists in tbl_users.
		int myUserID = getUserID(username);
		if (myUserID <= 0)
			return 0;

		// b) Enter keystore password.
		// c) Enter key password.
		// e) Load public-private key pair from keystore.
		KeyPair userKeyPair = getUserKeyPair(username);
		if (userKeyPair == null)
			return 0;

		// f) List available users.
		System.out.println("Available Users:");
		System.out.println("  ID     |    Username");
		System.out.println("---------+------------");
		try {
			Statement st = m_pg.createStatement();
			ResultSet rs = st.executeQuery("SELECT u_id, u_name FROM smea.tbl_users WHERE u_id != " + myUserID + " ORDER BY u_id;");
			while (rs.next())
			{
				System.out.println("  " + rightPad(rs.getString(1), 6, ' ') + "|  " + rs.getString(2));
			}
			rs.close();
			st.close();
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		
		int friendID = 0;
		PublicKey friendPublicKey = null;
		byte[] mekForSending = "".getBytes();
		byte[] mekForReading = "".getBytes();
		String SQL = "INSERT INTO smea.tbl_friends(f_from_u_id, f_to_u_id, f_mek_for_sending, f_mek_for_reading) VALUES(?, ?, ?, ?)";

		int count = 0;

		try {
			PreparedStatement insFriend = m_pg.prepareStatement(SQL);
			count = 0;

			while (true) {
				// g) Select a friend.
				String tmp = getUserInput("Enter ID of user to make friend (0 to quit):");
				friendID = Integer.parseInt(tmp);
				if (friendID == 0) {
					insFriend.close();
					return count;
				}

				// h) Get friend’s public key from the tbl_users.
				try {
					Statement st = m_pg.createStatement();
					ResultSet rs = st.executeQuery("SELECT u_public_key FROM smea.tbl_users WHERE u_id = " + friendID + ";");
					while (rs.next()) {
						byte[] fpk = rs.getBytes(1);
						EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(fpk);
						try {
							KeyFactory keyFactory = KeyFactory.getInstance("RSA");
							friendPublicKey = keyFactory.generatePublic(publicKeySpec);
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
					rs.close();
					st.close();
				} catch (SQLException ex) {
					System.out.println(ex.getMessage());
				}

				// i) Generate a secret key.
				SecureRandom sr = new SecureRandom();
				byte[] key = new byte[16];
				sr.nextBytes(key); // 128 bit key
				byte[] initVector = new byte[16];
				sr.nextBytes(initVector); // 16 bytes IV

				ByteBuffer bb = ByteBuffer.allocate(32);
				bb.put(key);
				bb.put(initVector);

				String cipherName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
				try {
					Cipher cipher = Cipher.getInstance(cipherName);

					// j) Encrypt the secret key using your own public key and store in f_mek_for_sending.
					cipher.init(Cipher.ENCRYPT_MODE, userKeyPair.getPublic());
					mekForSending = cipher.doFinal(bb.array());

					// k) Encrypt the secret key using friend’s public key and store in f_mek_for_reading.
					cipher.init(Cipher.ENCRYPT_MODE, friendPublicKey);
					mekForReading = cipher.doFinal(bb.array());
				} catch (Exception e) {
					e.printStackTrace();
				}

				// l) Insert row in tbl_friends.

				insFriend.setInt(1, myUserID);
				insFriend.setInt(2, friendID);
				insFriend.setBytes(3, mekForSending);
				insFriend.setBytes(4, mekForReading);

				insFriend.executeUpdate();
				count++;
			}
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		return count;
	}

	public static int sendMsg() {
		// a) Enter username.
		String username = getUserInput("Enter your username (q to quit):");
		if (username.length() <= 1)
			return 0;

		// d) Confirm username exists in tbl_users.
		int myUserID = getUserID(username);
		if (myUserID <= 0)
			return 0;

		// b) Enter keystore password.
		// c) Enter key password.
		// e) Load public-private key pair from keystore.
		KeyPair userKeyPair = getUserKeyPair(username);
		if (userKeyPair == null)
			return 0;

		// f) List available friends.
		System.out.println("Available Friends:");
		System.out.println("  ID     |    Friend name");
		System.out.println("---------+---------------");
		try {
			Statement st = m_pg.createStatement();
			ResultSet rs = st.executeQuery("SELECT f_to_u_id, u_name FROM smea.tbl_users, smea.tbl_friends WHERE u_id = f_to_u_id AND f_from_u_id = " + myUserID + " ORDER BY 1;");
			while (rs.next())
			{
				System.out.println("  " + rightPad(rs.getString(1), 6, ' ') + "|  " + rs.getString(2));
			}
			rs.close();
			st.close();
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}

		// g) Select a friend to send message to.
		int friendID = 0;
		String tmp = getUserInput("Enter ID of the friend to send the message to (0 to quit):");
		friendID = Integer.parseInt(tmp);
		if (friendID == 0) {
			return 0;
		}

		// h) Get the message encryption key (f_mek_for_sending) from tbl_friends.
		int fID = 0;
		byte[] meks = "".getBytes();
		try {
			Statement st = m_pg.createStatement();
			ResultSet rs = st.executeQuery("SELECT f_id, f_mek_for_sending FROM smea.tbl_friends WHERE f_from_u_id = " + myUserID + " AND f_to_u_id = " + friendID + ";");
			rs.next();
			fID = Integer.parseInt(rs.getString(1));
			meks = rs.getBytes(2);
			rs.close();
			st.close();
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}

		// i) Decrypt  f_mek_for_sending using your private key to get secret key.
		byte[] mek = "".getBytes();
		String cipherName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
		//Can use other cipher names, like "RSA/ECB/PKCS1Padding"
		try {
			Cipher cipher = Cipher.getInstance(cipherName);
			cipher.init(Cipher.DECRYPT_MODE, userKeyPair.getPrivate());
			mek = cipher.doFinal(meks);
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (mek.length != 32) {
			System.out.println("The system was unable to decrypt message encryption key for sending");
			return 0;
		}

		byte[] key = new byte[16];
		byte[] initVector = new byte[16];
		for (int i = 0; i < 16; i++) {
			key[i] = mek[i];
		}
		for (int i = 16; i < 32; i++) {
			initVector[i-16] = mek[i];
		}

		String SQL = "INSERT INTO smea.tbl_messages(m_f_id, m_message, m_sent_on) VALUES(?, ?, ?)";

		int count = 0;

		try {
			PreparedStatement insMessage = m_pg.prepareStatement(SQL);
			count = 0;

			while (true) {
				// j) Enter message to send.
				String msgToSend = getUserInput("Enter the message (q to quit):");
				if (msgToSend.length() <= 1) {
					insMessage.close();
					return count;
				}

				insMessage.setInt(1, fID);
				String encryptedMsg = "";
				// k) Encrypt message using secret key.
				try {
					encryptedMsg = encryptMessage(key, initVector, msgToSend);
				} catch (Exception e) {
					e.printStackTrace();
				}
				insMessage.setString(2, encryptedMsg);
				Calendar calendar = Calendar.getInstance();
				Timestamp ts = new Timestamp(calendar.getTime().getTime());
				insMessage.setTimestamp(3, ts);

				// l) Insert row in tbl_messages.
				insMessage.executeUpdate();
				count++;
			}
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}
		return count;
	}

	public static int readMsg() {
		// a) Enter username.
		String username = getUserInput("Enter your username (q to quit):");
		if (username.length() <= 1)
			return 0;

		// d) Confirm username exists in tbl_users.
		int myUserID = getUserID(username);
		if (myUserID <= 0)
			return 0;

		// b) Enter keystore password.
		// c) Enter key password.
		// e) Load public-private key pair from keystore.
		KeyPair userKeyPair = getUserKeyPair(username);
		if (userKeyPair == null)
			return 0;

		// f) List available message count from all friends.
		System.out.println("Available Messages:");
		System.out.println("  ID     |    Friend name   |  Message Count");
		System.out.println("---------+------------------+---------------");
		try {
			Statement st = m_pg.createStatement();
			ResultSet rs = st.executeQuery("SELECT smea.getSenderID (m_f_id) sender_id, smea.getSenderName(m_f_id) sender_name, count(m_f_id) msg_count FROM smea.tbl_messages WHERE m_f_id IN ( SELECT f_id FROM smea.tbl_friends WHERE f_to_u_id = " + myUserID + ") GROUP BY m_f_id ORDER BY 2");
			while (rs.next())
			{
				System.out.println("  " + rightPad(rs.getString(1), 6, ' ') + "|  " + rightPad(rs.getString(2), 15, ' ') +  "|  " + rs.getString(3));
			}
			rs.close();
			st.close();
		} catch (SQLException ex) {
			System.out.println(ex.getMessage());
		}

		int count = 0;

		while (true) {
			int friendID;
			System.out.println();
			System.out.println();

			// g) Select a friend to read messages from.
			String tmp = getUserInput("Enter ID of the friend to read the message from (0 to quit):");
			friendID = Integer.parseInt(tmp);
			if (friendID == 0) {
				return count;
			}

			// h) Get the message encryption key (f_mek_for_reading) from tbl_friends.
			int fID = 0;
			byte[] mekr = "".getBytes();
			try {
				Statement st = m_pg.createStatement();
				ResultSet rs = st.executeQuery("SELECT f_id, f_mek_for_reading FROM smea.tbl_friends WHERE f_to_u_id = " + myUserID + " AND f_from_u_id = " + friendID + ";");
				rs.next();
				fID = Integer.parseInt(rs.getString(1));
				mekr = rs.getBytes(2);
				rs.close();
				st.close();
			} catch (SQLException ex) {
				System.out.println(ex.getMessage());
			}


			// i) Decrypt  f_mek_for_reading using your private key to get secret key.
			byte[] mek = "".getBytes();
			String cipherName = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
			//Can use other cipher names, like "RSA/ECB/PKCS1Padding"
			try {
				Cipher cipher = Cipher.getInstance(cipherName);
				cipher.init(Cipher.DECRYPT_MODE, userKeyPair.getPrivate());
				mek = cipher.doFinal(mekr);
			} catch (Exception e) {
				e.printStackTrace();
			}

			if (mek.length != 32) {
				System.out.println("The system was unable to decrypt message encryption key for reading");
				return 0;
			}

			byte[] key = new byte[16];
			byte[] initVector = new byte[16];
			for (int i = 0; i < 16; i++) {
				key[i] = mek[i];
			}
			for (int i = 16; i < 32; i++) {
				initVector[i-16] = mek[i];
			}

			// j) List all messages from the selected friend by decrypting the messages using secret key.
			String SQL = "SELECT m_id, smea.getSenderName(m_f_id), m_sent_on, m_message FROM smea.tbl_messages WHERE m_f_id = " + fID + ";";

			System.out.println("Messages:");
			System.out.println("  ID   |   Friend Name    |    Sent On                  |    Message   ");
			System.out.println("-------+------------------+-----------------------------+------------------------------------");
			try {
				Statement st = m_pg.createStatement();
				ResultSet rs = st.executeQuery(SQL);
				while (rs.next())
				{
					count++;
					String dmsg = "";
					try {
						dmsg = decryptMessage(key, initVector, rs.getString(4));
					} catch (Exception e) {
						e.printStackTrace();
					}

					System.out.println("  " + rightPad(rs.getString(1), 4, ' ') + "|  " + rightPad(rs.getString(2), 15, ' ') + "|  " + rightPad(rs.getString(3), 26, ' ') + "|  " + dmsg);
				}
				rs.close();
				st.close();
			} catch (SQLException ex) {
				System.out.println(ex.getMessage());
			}
		}
	}

	private static boolean connectWithDb() {
		try {
			Class.forName("org.postgresql.Driver");
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Class Not Found : " + e.getMessage()); 
			return false;
		}

		try {
			m_pg = DriverManager.getConnection(m_url,
												m_user,
												m_password);
		} catch (SQLException e) {
			System.err.format("SQL State: %s\n%s", e.getSQLState(), e.getMessage());
			return false;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

    public static void main( String[] args )
    {
		String[] options = {"add-user", "add-friend", "send-messages", "read-messages"};
		final int ADD_USER = 0;
		final int ADD_FRIEND = 1;
		final int SEND_MSG = 2;
		final int READ_MSG = 3;
		int count = 0;
	
		if (args.length < 1) {
			System.out.println("The program expects either add-user, add-friend, send-messages or read-messages as command line argument");
			return;
		}
		
		int optionIndex = arrayContains(options, args[0]);
		
		if (optionIndex < 0) {
			System.out.println("The program expects either add-user, add-friend, send-messages or read-messages as command line argument");
			return;
		}

		connectWithDb();

		switch (optionIndex) {
			case ADD_USER:
				count = addUser();
				System.out.println("Added " + count + " users");
			break;
			case ADD_FRIEND:
				count = addFriend();
				System.out.println("Added " + count + " friends");
			break;
			case SEND_MSG:
				count = sendMsg();
				System.out.println("Sent " + count + " messages");
			break;
			case READ_MSG:
				count = readMsg();
				System.out.println("Read " + count + " messages");
			break;
		}
    }
}
