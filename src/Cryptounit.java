import java.io.*;
import javax.crypto.*;
import java.security.*;
import java.lang.RuntimeException;

public abstract class Cryptounit {

	public static byte[] encrypt(SecretKey key, Serializable obj) {
		try {
			final Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.ENCRYPT_MODE, key);
			return c.doFinal(serialize(obj));
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return null;
		}
	}

	public static byte[] encrypt(SecretKey key, byte[] plaintext) {
		try {
			final Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.ENCRYPT_MODE, key);
			return c.doFinal(plaintext);
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return null;
		}
	}

	public static Object decrypt(SecretKey key, byte[] cypherText) {
		try {
			final Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.DECRYPT_MODE, key);
			return deserialize(c.doFinal(cypherText));
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return null;
		}
	}


	public static byte[] serialize(Object obj) throws IOException {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream o = new ObjectOutputStream(b);
		o.writeObject(obj);
		return b.toByteArray();
	}

	public static Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
		ByteArrayInputStream b = new ByteArrayInputStream(bytes);
		ObjectInputStream o = new ObjectInputStream(b);
		return o.readObject();
	}


	public static byte[] sign(final String plaintext, final PrivateKey key) throws NoSuchProviderException, NoSuchAlgorithmException, SignatureException, InvalidKeyException  {
		Signature sig = Signature.getInstance("SHA256withRSA");
		sig.initSign(key);
		sig.update(plaintext.getBytes());

		return sig.sign();
	}

	public static boolean verify(final byte[] signature, final String plaintext, final PublicKey key) {
		try {
			Signature sig = Signature.getInstance("SHA256withRSA");
			sig.initVerify(key);
			sig.update(plaintext.getBytes());
			return sig.verify(signature);
		} catch (Exception e) {
			e.printStackTrace(System.err);
			return false;
		}
	}



	public static byte[] calcHMAC(SecretKey key, Serializable obj) throws Exception {
		Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
		sha256_HMAC.init(key);
		return sha256_HMAC.doFinal(serialize(obj));
	}

	public static byte[] hash(byte[] data) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			return digest.digest(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	

}