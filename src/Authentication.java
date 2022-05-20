import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;



public class Authentication {
	public static Map<String,Object> sendSocket(PublicKey publickey,PrivateKey privatekey,String BCADD) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception{
		byte[] publicBT =publickey.getEncoded(); 
	    int len1 = publicBT.length;
        // produce a random nonce
	    Random r = new Random();
        int nonce = r.nextInt(8999)+1000;
        byte[] srcBytes = crypto.inttobyte(nonce);
        int len2 = srcBytes.length;
		// decrypt by private key
        byte[] resultBytes = crypto.encrypt(privatekey, srcBytes);
        int len3 = resultBytes.length;
		DatagramSocket sendSocket = new DatagramSocket();
		InetAddress address = InetAddress.getLocalHost();
		String ip1 = address.getHostAddress();
		String BC_ADD = crypto.encode(publicBT);
        System.out.println("Sender's BCADD is:"+ BC_ADD);
        System.out.println("Sender's ADD is:"+ ip1);
        String other_address = Register.getIP(BCADD);
        InetAddress add = InetAddress.getByName(other_address);
        System.out.println("other_add"+other_address);
		int port = 12345;
		byte[] results = new byte[162];
		System.arraycopy(publicBT, 0, results, 0, len1);
		System.arraycopy(srcBytes, 0, results, len1-1, len2);
		System.arraycopy(resultBytes, 0, results, len1+len2-1, len3);
		DatagramPacket sendPacket = new DatagramPacket(results, results.length, add, port);
		// send data
		sendSocket.send(sendPacket);
		byte[] recevieByte = new byte[1024];
		int len = recevieByte.length;
		DatagramPacket receivePacket = new DatagramPacket(recevieByte, len);
		System.out.println("ok");
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
        byte[] decBytes = crypto.decrypt(publickey1, data3);
        int nonce1 = crypto.bytetoint(data2);
        int nonce2 = crypto.bytetoint(decBytes);
		// get IP of receiver
		InetAddress address1 = receivePacket.getAddress();
		String ip = address1.getHostAddress();
		String BC_ADD1 = crypto.encode(publicByte);
		System.out.println("Receiver's BCADD is:"+ BC_ADD1);
		System.out.println("Receiver's ADD is:"+ ip);
		System.out.println("Nonce is:" + nonce1);
		System.out.println("After decrypt:" + nonce2);
		int a = Register.call(BC_ADD1, ip);
		if(nonce1==nonce2 && a==1) {
			// generate session key by two nonces
			String s1 = String.valueOf(nonce);
			String s2 = String.valueOf(nonce1);
			String aesKey = s1 + s2 + s1 + s2 + s1 + s2 + s1 + s2;
			byte[] key = aesKey.getBytes();
			byte[] results2 = crypto.encrypt1(publickey1, key);
			DatagramPacket sendPacket2 = new DatagramPacket(results2, results2.length, add, port);
			// send data
			sendSocket.send(sendPacket2);
			sendSocket.close();
			Map<String,Object> res = new HashMap<>();
			res.put("key",key);
			res.put("add", add);
			return res;
		}else {
			byte[] ak = null;
			sendSocket.close();
			Map<String,Object> res = new HashMap<>();
			res.put("key",ak);
			res.put("add", add);
			return res;

		}
	}
	public static Map<String,Object> receiveSocket(PublicKey publickey,PrivateKey privatekey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception{
		int port = 12345;
		DatagramSocket receiveSocket = new DatagramSocket(port);
		byte[] receiveByte = new byte[1024];
		int len = receiveByte.length;
		DatagramPacket receivePacket = new DatagramPacket(receiveByte, len);
		receiveSocket.receive(receivePacket);
		byte[] dat = receivePacket.getData();
		byte[] data1 = new byte[94];
		System.arraycopy(dat, 0, data1, 0, 94);
		data1[93] = 1;
		byte[] data2 = new byte[4];
		System.arraycopy(dat, 93, data2, 0, 4);
		byte[] data3 = new byte[64];
		System.arraycopy(dat, 97, data3, 0, 64);
		// get key pair base on RSA
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey publickey_other = kf.generatePublic(new X509EncodedKeySpec(data1));
		byte[] publicByte = publickey_other.getEncoded();
		String BC_ADD= crypto.encode(publicByte);
		System.out.println("Sender's BCADD is:"+ BC_ADD);
		// encrypt by private key
		byte[] decBytes = crypto.decrypt(publickey_other, data3);
		int nonce1 = crypto.bytetoint(data2);
		int nonce2 = crypto.bytetoint(decBytes);
		InetAddress address = receivePacket.getAddress();
		String ip = address.getHostAddress();
		System.out.println("Sender's ADD is:"+ip);
		System.out.println("Nonce is:" + nonce1);
		System.out.println("After decrypt:" + nonce2);
		int a = Register.call(BC_ADD, ip);
		if(nonce1==nonce2 && a==1) {
			byte[] publicBT =publickey.getEncoded(); 
			int len1 = publicBT.length;
			// produce a random nonce
			Random r = new Random();
	        int nonce = r.nextInt(8999)+1000;
			byte[] srcBytes = crypto.inttobyte(nonce);
			int len2 = srcBytes.length;
			// encrypt by private key
			byte[] resultBytes = crypto.encrypt(privatekey, srcBytes);
			int len3 = resultBytes.length;
			byte[] results = new byte[162];
			System.arraycopy(publicBT, 0, results, 0, len1);
			System.arraycopy(srcBytes, 0, results, len1-1, len2);
			System.arraycopy(resultBytes, 0, results, len1+len2-1, len3);
			int port1 = receivePacket.getPort();
			// generate new datagram
			DatagramPacket sendPacket = new DatagramPacket(results, results.length, address, port1);
			// send data
			receiveSocket.send(sendPacket);
			// Receive session key
			DatagramPacket receivePacket2 = new DatagramPacket(receiveByte, len);
			receiveSocket.receive(receivePacket2);
			byte[] da2 = receivePacket2.getData();
			byte[] da1 = new byte[64];
			System.arraycopy(da2,0,da1,0,64);
			Map<String,Object> res = new HashMap<>();
			byte[] key = crypto.decrypt1(privatekey, da1);
			res.put("key",key);
			res.put("BCADD", BC_ADD);
			res.put("add", address);
			receiveSocket.close();
			return res;
		}else {
			Map<String,Object> res = new HashMap<>();
			receiveSocket.close();
			byte[] ak = null;
			res.put("key",ak);
			res.put("BCADD", BC_ADD);
			res.put("add", address);
			return res;
		}
	}
}


