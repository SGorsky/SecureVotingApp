import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.*;

public class EncryptRSA {
    public PrivateKey PRIV_KEY = null;
    public PublicKey PUB_KEY = null;

    public EncryptRSA() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair key = keyGen.generateKeyPair();

        PRIV_KEY = key.getPrivate();
        PUB_KEY = key.getPublic();
    }

    public String encrypt(String in, Key key) throws Exception {
        byte[] en = null;
        final Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        en = cipher.doFinal(in.getBytes("UTF8"));
        return new sun.misc.BASE64Encoder().encode(en);
    }

    public String decrypt(String in, Key key) throws Exception {
        byte[] de = null;
        final Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        de = cipher.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(in));
        return new String(de, "UTF8");
    }
}
