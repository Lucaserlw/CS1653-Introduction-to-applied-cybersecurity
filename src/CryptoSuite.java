import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.ArrayList;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;

/*
 * This class is meant to provide the basic operations necessary for our crypto suite to work well
 * Symmetric key: 256-bit AES with CBC and PKCS5Padding
 * Asymmetric key: 2048-bit RSA with SHA-256 for hashing
 * Passwords use a 64-bit salt
 */

public class CryptoSuite {
    private SecureRandom random;
    private Signature sign;
    private PrivateKey privateKey;
    private MessageDigest md;
    private Cipher aes;
    private Cipher rsa;


    public CryptoSuite(PublicKey _publicKey, PrivateKey _privateKey) {
        privateKey = _privateKey;

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        try {
            random = SecureRandom.getInstanceStrong();
            sign = Signature.getInstance("SHA256withRSA");
            md = MessageDigest.getInstance("SHA-256");
            aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            rsa = Cipher.getInstance("RSA");
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
    }

    private byte[] envelopeToBytes(Envelope env) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            ObjectOutputStream out = new ObjectOutputStream(bos);   
            out.writeObject(env);
            byte[] eBytes = bos.toByteArray();
            out.close();
            bos.close();
            return eBytes;
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    private Envelope bytesToEnvelope(byte[] eBytes) {
        ByteArrayInputStream bis = new ByteArrayInputStream(eBytes);
        try {
            ObjectInputStream ois = new ObjectInputStream(bis);
            return (Envelope) ois.readObject();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    private byte[] groupsToBytes(ArrayList<String> groups) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try {
            ObjectOutputStream out = new ObjectOutputStream(bos);   
            out.writeObject(groups);
            byte[] eBytes = bos.toByteArray();
            out.close();
            bos.close();
            return eBytes;
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    public Token signToken(String subject, ArrayList<String> groups, Envelope ht) {
        byte[] subjectBytes = subject.getBytes();
        byte[] groupBytes = groupsToBytes(groups);
        byte[] htBytes = envelopeToBytes(ht);
        try {
            sign.initSign(privateKey);
            sign.update(subjectBytes);
            sign.update(groupBytes);
            sign.update(htBytes);
            byte[] signature = sign.sign();
            return new Token(subject, groups, ht, signature);
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    public boolean verifyToken(UserToken token, PublicKey pubK) {
        try {
            byte[] subjectBytes = token.getSubject().getBytes();
            byte[] groupBytes = groupsToBytes(token.getGroups());
            byte[] htBytes = envelopeToBytes(token.getHostToken());
            sign.initVerify(pubK);
            sign.update(subjectBytes);
            sign.update(groupBytes);
            sign.update(htBytes);
            return sign.verify(token.getSignature());
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return false;
    }

    public byte[] generateSalt()
    {
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        return salt;
    }

    public SecretKey computeKey(String password, byte[] salt) {
        try {
            md.update(salt);
            byte[] hash = md.digest(password.getBytes());
            return new SecretKeySpec(hash, "AES");
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    // Returns byte[] since IvParameterSpec is not serializable
    public byte[] generateAesIv() {
        byte[] ivb = new byte[16];
        random.nextBytes(ivb);
        return ivb;
    }

    // This is stupid, but it encrypts an Envelope in AES and then returns an Envelope with the encrypted envelope nested inside of it
    // Returned envelope has encrypted byte[] at index 0 and initialization vector byte[] at index 1
    public Envelope encryptEnvelopeAES(Envelope env, String msg, Key key) {
        Envelope enc = new Envelope(msg);
        byte[] eBytes = envelopeToBytes(env);
        byte[] ivb = generateAesIv();
        IvParameterSpec iv = new IvParameterSpec(ivb);
        try {
            aes.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] encBytes = aes.doFinal(eBytes);
            enc.addObject(encBytes);
            enc.addObject(ivb);
            return enc;
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    public Envelope decryptEnvelopeAES(byte[] encBytes, byte[] ivb, Key key) {
        IvParameterSpec iv = new IvParameterSpec(ivb);
        try {
            aes.init(Cipher.DECRYPT_MODE, key, iv);
            byte[] eBytes = aes.doFinal(encBytes);
            return bytesToEnvelope(eBytes);
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    public byte[] encryptKeyRSA(SecretKey key, PublicKey pub) {
        try {
            rsa.init(Cipher.ENCRYPT_MODE, pub);
            byte[] encBytes = rsa.doFinal(key.getEncoded());
            return encBytes;
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    public SecretKey decryptKeyRSA(byte[] encBytes, PrivateKey priv) {
        try {
            rsa.init(Cipher.DECRYPT_MODE, priv);
            byte[] eBytes = rsa.doFinal(encBytes);
            return new SecretKeySpec(eBytes, "AES");
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    // Generates a 256-bit AES symmetric key
    public SecretKey generateKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256, random);
            return kg.generateKey();
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }
  
    // Returns a SHA-1 fingerprint converted to base 64
    public String getFingerprint(PublicKey pub) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(pub.getEncoded());
            return Base64.getEncoder().encodeToString(md.digest());
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    public byte[] encryptMessageAES(String message, SecretKey key, byte[] ivb) {
        try {
            IvParameterSpec iv = new IvParameterSpec(ivb);
            aes.init(Cipher.ENCRYPT_MODE, key, iv);
            return aes.doFinal(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    public String decryptStringAES(byte[] encMessage, SecretKey key, byte[] ivb) {
        try {
            IvParameterSpec iv = new IvParameterSpec(ivb);
            aes.init(Cipher.DECRYPT_MODE, key, iv);
            return new String(aes.doFinal(encMessage));
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return null;
    }

    // Using an 8-byte m
    // Inputs are validated such that n is no longer than 8 bytes
    public boolean checkProblem(byte[] m, byte[] n, int b) {
        try {
            md.update(m);
            byte[] hash = md.digest(n);
            int leading = 0;
            int i = 0;
            // Check all the leading 0-bytes
            while (hash[i] == 0) {
                leading += 8;
                i++;
            }
            // Using bitwise AND to check number of leading 0-bits in first non-zero byte
            for (int j = 7; ((-1 << j) & hash[i]) == 0; j--) {
                leading += 1;
            }
            if (leading >= b) return true;
        } catch (Exception e) {
            e.printStackTrace(System.out);
        }
        return false;
    }
}
