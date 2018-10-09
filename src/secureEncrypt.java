import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import static crypto.secureUtils.toHexString;

public class secureEncrypt {
    public static void main(String args[]) throws Exception{
        FileInputStream in_file;
        FileOutputStream out_file;

        try {
            //read file into byte array
            in_file = new FileInputStream(args[0]);
            byte[] msg = new byte[in_file.available()];
            in_file.read(msg);
            in_file.close();

            //create message digest
            byte[] messageDigest;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            messageDigest = digest.digest(msg);
            System.out.println("Your file's MD is: " + toHexString(messageDigest));


            //concatenate digest to file https://stackoverflow.com/a/9133993
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(msg);
            outputStream.write(messageDigest);
            byte[] messagePlusDigest = outputStream.toByteArray();
            System.out.println("Information to be encrypted is:" + toHexString(messagePlusDigest));

            //Generate Key
            byte[] seed = args[2].getBytes();
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed);
            keyGenerator.init(128,secureRandom);
            SecretKey secretKey = keyGenerator.generateKey();

            //Get key spec
            byte[] rawKey = secretKey.getEncoded();
            SecretKeySpec secretKeySpec = new SecretKeySpec(rawKey, "AES");

            //Generating initalization vector
            int initVectSize = 16;
            byte[] initvector = new byte[initVectSize];
            SecureRandom random = new SecureRandom();
            random.nextBytes(initvector);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initvector);

            //Encrypting
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encrypted = cipher.doFinal(messagePlusDigest);

            //Combine IV vectors for decryption
            outputStream.reset();
            outputStream.write(encrypted);
            outputStream.write(initvector);
            byte[] encryptedandIV = outputStream.toByteArray();

            out_file = new FileOutputStream(args[1]);
            out_file.write(encryptedandIV);
            out_file.close();
            System.out.println("Encryption Finished.");
        }catch (Exception except){
            except.printStackTrace();
        }
    }
}
