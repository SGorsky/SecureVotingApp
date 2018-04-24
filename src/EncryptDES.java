import java.security.Key;
import javax.crypto.*;

public class EncryptDES{
    private Cipher encryptCipher;
    private Cipher decryptCipher;

    public EncryptDES(Key sk) throws Exception{
        encryptCipher = Cipher.getInstance("DES");
        encryptCipher.init(Cipher.ENCRYPT_MODE,sk);
        decryptCipher = Cipher.getInstance("DES");
        decryptCipher.init(Cipher.DECRYPT_MODE,sk);
    }

    public String encrypt(String plaintext) throws Exception{
        byte[] utf8 = plaintext.getBytes("UTF8");
        byte[] encrypted = encryptCipher.doFinal(utf8); 
        return new sun.misc.BASE64Encoder().encode(encrypted);
    }

    public String decrypt(String encryptedText) throws Exception{
        byte[] decrypted = new sun.misc.BASE64Decoder().decodeBuffer(encryptedText);
        byte[] utf8 = decryptCipher.doFinal(decrypted);
        return new String(utf8,"UTF8");
    }
}