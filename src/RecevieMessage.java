import java.net.DatagramPacket;
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
import java.math.BigInteger;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;


public class RecevieMessage extends EncrypRSA{
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,Exception {
        EncrypRSA rsa = new EncrypRSA();
        int port = 12345;
        DatagramSocket recevieSocket = new DatagramSocket(port);
        byte[] receiveByte = new byte[1024];
        int len = receiveByte.length;
        DatagramPacket receviePacket = new DatagramPacket(receiveByte, len);
        recevieSocket.receive(receviePacket);
        byte[] dat = receviePacket.getData();
        byte[] data1 = new byte[94];
        System.arraycopy(dat, 0, data1, 0, 94);
        data1[93] = 1;
        byte[] data2 = new byte[4];
        System.arraycopy(dat, 93, data2, 0, 4);
        byte[] data3 = new byte[64];
        System.arraycopy(dat, 97, data3, 0, 64);
        // get key pair base on RSA
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publickey = kf.generatePublic(new X509EncodedKeySpec(data1));
        byte[] publicByte =publickey.getEncoded();
        String BC_ADD=encode(publicByte);
        System.out.println("Sender's BCADD is:"+ BC_ADD);
        // encrypt by private key
        byte[] decBytes = rsa.decrypt(publickey, data3);
        int nonce1 = bytetoint(data2);
        int nonce2 = bytetoint(decBytes);
        InetAddress address = receviePacket.getAddress();
        String ip = address.getHostAddress();
        System.out.println("Sender's ADD is:"+ip);
        System.out.println("Nonce is：" + nonce1);
        System.out.println("After decrypt：" + nonce2);
        String blockchainNode = "http://127.0.0.1:7545/";
        Web3j web3 = Web3j.build(new HttpService(blockchainNode));
        Credentials credentials;
        credentials = Credentials.create("426c2ceda43bf8e1b722c648de2c419ce629d6507577dd41ddccfa5856eba3b3");
        String contractAddr = "0xd1F331140cb4Aa2b7B16391a77C74d2485f85BAc";
        @SuppressWarnings("deprecation")
        BERAN3 contract = BERAN3.load(contractAddr, web3, credentials, BERAN3.GAS_PRICE, BERAN3.GAS_LIMIT);
        BigInteger be = contract.call(BC_ADD,ip).send();
        System.out.println(be);
        int a =Integer.valueOf(be.toString());
        if(nonce1==nonce2 && a==1 ) {
            System.out.println("Authantication succeed");
            //send message
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(512);
            // generate a key pair
            KeyPair keyPair = keyPairGen.generateKeyPair();
            // get private key
            PrivateKey privateKey = (PrivateKey)keyPair.getPrivate();
            // get public key
            PublicKey publicKey1 = (PublicKey)keyPair.getPublic();
            byte[] publicBT =publicKey1.getEncoded(); //公钥转换为bytes
            int len1 = publicBT.length;
            // let nonce = 9999
            int nonce = 9999;
            byte[] srcBytes = inttobyte(nonce);
            int len2 = srcBytes.length;
            // encrypt by private key
            byte[] resultBytes = rsa.encrypt(privateKey, srcBytes);
            int len3 = resultBytes.length;
            byte[] results = new byte[162];
            System.arraycopy(publicBT, 0, results, 0, len1);
            System.arraycopy(srcBytes, 0, results, len1-1, len2);
            System.arraycopy(resultBytes, 0, results, len1+len2-1, len3);
            // get IP and port number
            InetAddress address1 = InetAddress.getLocalHost();
            String ip1 = address1.getHostAddress();
            int port1 = receviePacket.getPort();
            String BC_ADD1=encode(publicBT);
            System.out.println("Receiver's BCADD is:"+ BC_ADD1);
            System.out.println("Receiver's ADD is:"+ ip1);
            TransactionReceipt recp = contract.upload(BC_ADD1,ip1).send();
            // generate new datagram
            DatagramPacket sendPacket = new DatagramPacket(results, results.length, address, port1);
            // send data
            recevieSocket.send(sendPacket);
            DatagramPacket receviePacket2 = new DatagramPacket(receiveByte, len);
            // receive data
            recevieSocket.receive(receviePacket2);
            byte[] da2 = receviePacket2.getData();
            byte[] da1 = new byte[64];
            System.arraycopy(da2,0,da1,0,64);
            byte[] key = rsa.decrypt1(privateKey, da1);
            System.out.println("Received seesion key");
            while(true) {
                Scanner in = new Scanner(System.in);
                String message = in.nextLine();
                String Results1 = AESEncrypt.Aes256Encode(message, key);
                byte[] results1 = Results1.getBytes("UTF-8");
                DatagramPacket sendPacket1 = new DatagramPacket(results1, results1.length, address, port1);
                // send data
                recevieSocket.send(sendPacket1);
                if(message.equals("end")) {
                    in.close();
                    break;
                }
                DatagramPacket receviePacket1 = new DatagramPacket(receiveByte, len);
                // receive data
                recevieSocket.receive(receviePacket1);
                byte[] dat2 = receviePacket1.getData();
                byte[] dat1 = new byte[24];
                System.arraycopy(dat2,0,dat1,0,24);
                String Result = new String(dat1,"UTF-8");
                String Receiv = AESEncrypt.Aes256Decode(Result, key);
                System.out.println("收到信息："+Receiv);
                if(Receiv.equals("end")) {
                    break;
                }
            }
            recevieSocket.close();

        }else {
            recevieSocket.close();
        }
    }
}
