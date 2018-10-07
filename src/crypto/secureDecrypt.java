package crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

import java.util.Arrays;
import static crypto.secureUtils.toHexString;

public class secureDecrypt {

    public static void main(String args[]){
        FileInputStream in_file = null;
        FileOutputStream out_file = null;
        try {
            //get ciphertext
            in_file = new FileInputStream(args[0]);
            byte[] cipherText = new byte[in_file.available()];
            in_file.read(cipherText);
            in_file.close();


            //Generate Key
            byte[] seed = args[2].getBytes();
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed);
            keyGenerator.init(128,secureRandom);
            SecretKey secretKey = keyGenerator.generateKey();

            byte[] rawKey = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(rawKey, "AES");


            //Generating initalization vector
            int initVectSize = 16;
            byte[] initvector = new byte[initVectSize];
            SecureRandom random = new SecureRandom();
            random.nextBytes(initvector);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initvector);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedMessage = cipher.doFinal(cipherText);

            int fileSize =  decryptedMessage.length - initvector.length - 32;
            byte[] plaintext = Arrays.copyOfRange(decryptedMessage,0,fileSize);
            byte[] plaintexthash = Arrays.copyOfRange(decryptedMessage,fileSize +initvector.length,decryptedMessage.length);

            //create message digest
            byte[] messageDigest;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            messageDigest = digest.digest(plaintext);
            System.out.println("The plaintext's Message Digest is: " + toHexString(messageDigest));

            if (Arrays.equals(messageDigest,plaintexthash)){
                System.out.println("The hashes match!");
            } else {
                System.out.println("The hashes DO NOT match!");
            }

            out_file = new FileOutputStream(args[1]);
            out_file.write(plaintext);
            out_file.close();
            System.out.println("Encryption Finished.");
        }catch (Exception except){
            System.out.println(except);
        }
    }
}
