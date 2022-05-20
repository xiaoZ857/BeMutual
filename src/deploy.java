import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.RawTransactionManager;
import org.web3j.tx.TransactionManager;



//courtesy
//this class is provided for us to deploy new version of BERAN smart contract on ethereum (warning: The previous data is still stored in the previous contract account )
public class deploy {
	
	static String walletDirectory = "C:/Download";
    static String walletName = "UTC--2021-07-27T15-55-48.312753850Z--3ab14f15648bdca5216f67a36725fc3129fec9f1";
	static int CHAINID =  666;
//    
	//declaration of some variables are used to create credential and transaction manager
//    static int CHAINID = 5777;
//    static String account_address= "0x51577f0DB15aF6d8e8758Ce588745624bc075d9D";
//    static String private_key = "9bb39543bf9ceb8693f54cb563ef2c6e9d03cd500314c4d613badffbd5eec887";
	public static void main(String[] args) throws Exception, Exception {
		//Connecting to our ethereum private chain
	    System.out.println("Connecting to Ethereum ...");
//	    Web3j web3j = Web3j.build(new HttpService("http://localhost:7545"));
	    Web3j web3j = Web3j.build(new HttpService("http://18.134.41.239:7545"));
	    System.out.println("Successfuly connected to Ethereum");
	    //Path path = Paths.get(walletDirectory+"/random_key.txt");
	 	String walletPassword = "123456";//"123456";//Files.readString(path);
	    // two ways to create credentials which are required when you send transaction(including deploy smart contract, call functions of smart contract )
        Credentials credentials = WalletUtils.loadCredentials(walletPassword, walletDirectory + "/" + walletName);
        TransactionManager transactionManager = new RawTransactionManager(web3j, credentials, (byte) CHAINID);//create a transaction manager to send transaction
        try {

        	// ͨ����Լ��װ������в���
			long startTime = System.currentTimeMillis();
			@SuppressWarnings("deprecation")
			BERAN Contract = BERAN.deploy(web3j, transactionManager, BERAN.GAS_PRICE, BERAN.GAS_LIMIT).send();
			long endTime = System.currentTimeMillis();
			// ��ȡ��Լ��ַ
			String addr = Contract.getContractAddress();
			System.out.println("Contract " + addr + " has been deployed:" + (endTime - startTime) + " ms");

        } catch (Exception e) {
            e.printStackTrace();
        }

	}

   

    


}
