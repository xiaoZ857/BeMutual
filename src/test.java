import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class test {
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception{
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(512);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = (PrivateKey)keyPair.getPrivate();             
        PublicKey publicKey = (PublicKey)keyPair.getPublic();
        
        byte[] publicBT =publicKey.getEncoded();
        System.out.println(new String(publicBT));
        String str=crypto.encode(publicBT);
        System.out.println(str);
        System.out.println(str.length());
        byte[] output=crypto.decode(str);
        System.out.println(new String(output));
        Random r = new Random();
        int i1 = r.nextInt(8999)+1000;
        System.out.println(i1);
        byte[] srcBytes = crypto.inttobyte(i1);
        int nonce1 = crypto.bytetoint(srcBytes);
        System.out.println(nonce1);
        String stri = String.valueOf(nonce1);
        String s = stri + stri;
        System.out.println(s);
    }

}
