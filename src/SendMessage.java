import java.net.DatagramPacket;
import java.math.BigInteger;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Base64;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


public class SendMessage extends EncrypRSA{
    public static final String ALGORITHM = "AES/ECB/PKCS7Padding";
    static{
        try{
            Security.addProvider(new BouncyCastleProvider());
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    public static String Aes256Encode(String str, byte[] key) {
        byte[] result = null;
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            result = cipher.doFinal(str.getBytes("UTF-8"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new String(Base64.getEncoder().encode(result));
    }

    public static String Aes256Decode(String str, byte[] key) {
        byte[] bytes = Base64.getDecoder().decode(str);
        String result = null;
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
            byte[] decoded = cipher.doFinal(bytes);
            result = new String(decoded, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception {
        String blockchainNode = "http://127.0.0.1:7545/";
        Web3j web3 = Web3j.build(new HttpService(blockchainNode));
        Credentials credentials;
        credentials = Credentials.create("426c2ceda43bf8e1b722c648de2c419ce629d6507577dd41ddccfa5856eba3b3");
        String contractAddr = "0xd1F331140cb4Aa2b7B16391a77C74d2485f85BAc";// address of smart contrast
        @SuppressWarnings("deprecation")
        BERAN3 contract = BERAN3.load(contractAddr, web3, credentials, BERAN3.GAS_PRICE, BERAN3.GAS_LIMIT);
        EncrypRSA rsa = new EncrypRSA();
        // KeyPairGenerator base on RSA
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(512);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = (PrivateKey)keyPair.getPrivate();
        PublicKey publicKey = (PublicKey)keyPair.getPublic();
        byte[] publicBT =publicKey.getEncoded(); //��Կת��Ϊbytes
        int len1 = publicBT.length;
        // let nonce equal to 6666
        int nonce = 6666;
        byte[] srcBytes = inttobyte(nonce);
        int len2 = srcBytes.length;
        // decrypt by private key
        byte[] resultBytes = rsa.encrypt(privateKey, srcBytes);
        int len3 = resultBytes.length;
        DatagramSocket sendSocket = new DatagramSocket();
        InetAddress address = InetAddress.getLocalHost();
        String ip1 = address.getHostAddress();
        String BC_ADD=encode(publicBT);
        System.out.println("Sender's BCADD is:"+ BC_ADD);
        System.out.println("Sender's ADD is:"+ ip1);
        TransactionReceipt recp = contract.upload(BC_ADD,ip1).send();
        int port = 12345;
        byte[] results = new byte[162];
        System.arraycopy(publicBT, 0, results, 0, len1);
        System.arraycopy(srcBytes, 0, results, len1-1, len2);
        System.arraycopy(resultBytes, 0, results, len1+len2-1, len3);
        DatagramPacket sendPacket = new DatagramPacket(results, results.length, address, port);
        // send data
        sendSocket.send(sendPacket);
        byte[] recevieByte = new byte[1024];
        int len = recevieByte.length;
        DatagramPacket receivePacket = new DatagramPacket(recevieByte, len);
        // receive data
        sendSocket.receive(receivePacket);
        byte[] dat = receivePacket.getData();
        byte[] data1 = new byte[94];
        System.arraycopy(dat, 0, data1, 0, 94);
        data1[93] = 1;
        byte[] data2 = new byte[4];
        System.arraycopy(dat, 93, data2, 0, 4);
        byte[] data3 = new byte[64];
        System.arraycopy(dat, 97, data3, 0, 64);
        // get public key
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publickey1 = kf.generatePublic(new X509EncodedKeySpec(data1));
        byte[] publicByte =publickey1.getEncoded();
        // encrypt by public key
        byte[] decBytes = rsa.decrypt(publickey1, data3);
        int nonce1 = bytetoint(data2);
        int nonce2 = bytetoint(decBytes);
        // get IP of receiver
        InetAddress address1 = receivePacket.getAddress();
        String ip = address1.getHostAddress();
        String BC_ADD1=encode(publicByte);
        System.out.println("Receiver's BCADD is:"+ BC_ADD1);
        System.out.println("Receiver's ADD is:"+ ip);
        System.out.println("Nonce is��" + nonce1);
        System.out.println("After decrypt��" + nonce2);
        BigInteger be = contract.call(BC_ADD1,ip).send();
        System.out.println(be);
        int a =Integer.valueOf(be.toString());
        if(nonce1==nonce2 && a==1) {
            System.out.println("Authantication succeed");
            // generate session key
            String aesKey = "66669999666699996666999966669999";
            byte[] key = aesKey.getBytes();
            byte[] results2 = rsa.encrypt1(publickey1, key);
            DatagramPacket sendPacket2 = new DatagramPacket(results2, results2.length, address, port);
            // send data
            sendSocket.send(sendPacket2);
            while(true) {
                // receive data
                DatagramPacket receviePacket1 = new DatagramPacket(recevieByte, len);
                sendSocket.receive(receviePacket1);
                byte[] dat2 = receviePacket1.getData();
                byte[] dat1 = new byte[24];
                System.arraycopy(dat2,0,dat1,0,24);
                String Result = new String(dat1,"UTF-8");
                String Receiv = AESEncrypt.Aes256Decode(Result, key);
                System.out.println("�յ���Ϣ��"+Receiv);
                if(Receiv.equals("end")) {
                    break;
                }
                Scanner s= new Scanner(System.in);
                String result1 = s.nextLine();
                String Results1 = AESEncrypt.Aes256Encode(result1, key);
                byte[] results1 = Results1.getBytes("UTF-8");
                DatagramPacket sendPacket1 = new DatagramPacket(results1, results1.length, address, port);
                // send data
                sendSocket.send(sendPacket1);
                if(result1.equals("end")) {
                    s.close();
                    break;
                }
            }
            sendSocket.close();
        }else {
            // close source
            sendSocket.close();
        }
    }
}
