import java.math.BigInteger;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;


public class Register {
	static String walletDirectory = "./";
    static String walletName = "UTC--2021-07-27T15-55-48.312753850Z--3ab14f15648bdca5216f67a36725fc3129fec9f1";
	static int CHAINID =  666;
	public static String generateBCADD(PublicKey publickey) {
		byte[] publicBT =publickey.getEncoded(); 
		String BC_ADD = crypto.encode(publicBT); //hash base 58
		return BC_ADD;
	}

	public static void upload(String BCADD) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception{
		String blockchainNode = "http://18.134.41.239:7545/";
		Web3j web3 = Web3j.build(new HttpService(blockchainNode));
		String walletPassword = "123456";
		Credentials credentials = WalletUtils.loadCredentials(walletPassword, walletDirectory + "/" + walletName);
		String contractAddr = "0x85edfe6b684744eff7e36c8b97e222eb61da9793";// address of smart contrast		
		@SuppressWarnings("deprecation")
		BERAN contract = BERAN.load(contractAddr, web3, credentials, BERAN.GAS_PRICE, BERAN.GAS_LIMIT);
		InetAddress address = InetAddress.getLocalHost();
		String ip1 = address.getHostAddress();
		System.out.println("Sender's BCADD is:"+ BCADD);
        System.out.println("Sender's ADD is:"+ ip1);
        TransactionReceipt recp = contract.upload(BCADD,ip1).send();
        System.out.println("blockNumber:" + recp.getBlockNumber());
	}
	public static int call(String BC_ADD1, String ip) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception{
		String blockchainNode = "http://18.134.41.239:7545/";
		Web3j web3 = Web3j.build(new HttpService(blockchainNode));
		String walletPassword = "123456";
		Credentials credentials = WalletUtils.loadCredentials(walletPassword, walletDirectory + "/" + walletName);
		String contractAddr = "0x85edfe6b684744eff7e36c8b97e222eb61da9793";// address of smart contrast		
		@SuppressWarnings("deprecation")
		BERAN contract = BERAN.load(contractAddr, web3, credentials, BERAN.GAS_PRICE, BERAN.GAS_LIMIT);
		BigInteger be = contract.call(BC_ADD1,ip).send();
		System.out.println(be);
		int a = Integer.valueOf(be.toString());
		return a;
	}
	public static String getIP(String BCADD) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, Exception{
		String blockchainNode = "http://18.134.41.239:7545/";
		Web3j web3 = Web3j.build(new HttpService(blockchainNode));
		String walletPassword = "123456";
		Credentials credentials = WalletUtils.loadCredentials(walletPassword, walletDirectory + "/" + walletName);
		String contractAddr = "0x85edfe6b684744eff7e36c8b97e222eb61da9793";// address of smart contrast		
		@SuppressWarnings("deprecation")
		BERAN contract = BERAN.load(contractAddr, web3, credentials, BERAN.GAS_PRICE, BERAN.GAS_LIMIT);
		String add = contract.ADD_match(BCADD).send();
		System.out.println("add is:"+add);
		return add;
	}

}
