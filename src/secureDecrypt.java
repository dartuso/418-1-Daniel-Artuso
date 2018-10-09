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
        FileInputStream in_file;
        FileOutputStream out_file;
        try {
            //get ciphertext
            in_file = new FileInputStream(args[0]);
            byte[] cipherTextAndIV = new byte[in_file.available()];
            in_file.read(cipherTextAndIV);
            in_file.close();


            //Generate Key and get SecretKeySpec
            byte[] seed = args[2].getBytes();
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed);
            keyGenerator.init(128,secureRandom);
            SecretKey secretKey = keyGenerator.generateKey();
            byte[] rawKey = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(rawKey, "AES");

            //Get IV's from ciphertext
            byte[] initVector = Arrays.copyOfRange(cipherTextAndIV,cipherTextAndIV.length - 16,cipherTextAndIV.length);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initVector);

            //Get ciphertext without IV's
            byte[] cipherText = Arrays.copyOfRange(cipherTextAndIV,0,cipherTextAndIV.length - 16);

            //Do decryption
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decryptedMessage = cipher.doFinal(cipherText);

            //Split decrypted message into message and hash
            int fileSize =  decryptedMessage.length - 32;
            byte[] plaintext = Arrays.copyOfRange(decryptedMessage,0,fileSize);
            byte[] plaintexthash = Arrays.copyOfRange(decryptedMessage,decryptedMessage.length -32, decryptedMessage.length);
            System.out.println("The encrypted's hash is: " + toHexString(plaintexthash));

            //create message digest
            byte[] messageDigest;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            messageDigest = digest.digest(plaintext);
            System.out.println("The plaintext's hash is: " + toHexString(messageDigest));

            //Compare Hashes
            if (Arrays.equals(messageDigest,plaintexthash)){
                System.out.println("The hashes match!");
            } else {
                System.out.println("The hashes DO NOT match!");
            }

            //Write output file
            out_file = new FileOutputStream(args[1]);
            out_file.write(plaintext);
            out_file.close();
            System.out.println("Decryption Finished.");
        }catch (Exception except){
            System.err.println(except);
        }
    }
}
