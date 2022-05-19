import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collections;
import org.web3j.abi.TypeReference;
import org.web3j.abi.datatypes.Function;
import org.web3j.abi.datatypes.Type;
import org.web3j.abi.datatypes.generated.Uint8;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.RemoteCall;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.tx.Contract;
import org.web3j.tx.TransactionManager;

/**
 * <p>Auto generated code.
 * <p><strong>Do not modify!</strong>
 * <p>Please use the <a href="https://docs.web3j.io/command_line.html">web3j command line tools</a>,
 * or the org.web3j.codegen.SolidityFunctionWrapperGenerator in the 
 * <a href="https://github.com/web3j/web3j/tree/master/codegen">codegen module</a> to update.
 *
 * <p>Generated with web3j version 3.5.0.
 */
public class BERAN3 extends Contract {
    private static final String BINARY = "608060405234801561001057600080fd5b5061059c806100206000396000f30060806040526004361061004c576000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff168063202e49361461005157806379a789bb14610100575b600080fd5b34801561005d57600080fd5b506100fe600480360381019080803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290803590602001908201803590602001908080601f01602080910402602001604051908101604052809392919081815260200183838082843782019150505050505091929192905050506101c9565b005b34801561010c57600080fd5b506101ad600480360381019080803590602001908201803590602001908080601f0160208091040260200160405190810160405280939291908181526020018383808284378201915050505050509192919290803590602001908201803590602001908080601f016020809104026020016040519081016040528093929190818152602001838380828437820191505050505050919291929050505061024d565b604051808260ff1660ff16815260200191505060405180910390f35b806000836040518082805190602001908083835b60208310151561020257805182526020820191506020810190506020830392506101dd565b6001836020036101000a038019825116818451168082178552505050505050905001915050908152602001604051809103902090805190602001906102489291906104cb565b505050565b600080826040516020018080602001828103825283818151815260200191508051906020019080838360005b83811015610294578082015181840152602081019050610279565b50505050905090810190601f1680156102c15780820380516001836020036101000a031916815260200191505b50925050506040516020818303038152906040526040518082805190602001908083835b60208310151561030a57805182526020820191506020810190506020830392506102e5565b6001836020036101000a0380198251168184511680821785525050505050509050019150506040518091039020600019166000856040518082805190602001908083835b602083101515610373578051825260208201915060208101905060208303925061034e565b6001836020036101000a038019825116818451168082178552505050505050905001915050908152602001604051809103902060405160200180806020018281038252838181546001816001161561010002031660029004815260200191508054600181600116156101000203166002900480156104325780601f1061040757610100808354040283529160200191610432565b820191906000526020600020905b81548152906001019060200180831161041557829003601f168201915b5050925050506040516020818303038152906040526040518082805190602001908083835b60208310151561047c5780518252602082019150602081019050602083039250610457565b6001836020036101000a03801982511681845116808217855250505050505090500191505060405180910390206000191614156104bc57600190506104c1565b600090505b8091505092915050565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061050c57805160ff191683800117855561053a565b8280016001018555821561053a579182015b8281111561053957825182559160200191906001019061051e565b5b509050610547919061054b565b5090565b61056d91905b80821115610569576000816000905550600101610551565b5090565b905600a165627a7a72305820ff15a14aa044f40b10cd4d59c231603c057b3c82713b21ed87684adbf4a55af50029\r\n";

    public static final String FUNC_UPLOAD = "upload";

    public static final String FUNC_CALL = "call";

    @SuppressWarnings("deprecation")
    protected BERAN3(String contractAddress, Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    @SuppressWarnings("deprecation")
    protected BERAN3(String contractAddress, Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        super(BINARY, contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }

    public RemoteCall<TransactionReceipt> upload(String _BCADD, String _ADD) {
        final Function function = new Function(
                FUNC_UPLOAD,
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Utf8String(_BCADD),
                        new org.web3j.abi.datatypes.Utf8String(_ADD)),
                Collections.<TypeReference<?>>emptyList());
        return executeRemoteCallTransaction(function);
    }

    public RemoteCall<BigInteger> call(String _BCADD, String _ADD) {
        final Function function = new Function(FUNC_CALL,
                Arrays.<Type>asList(new org.web3j.abi.datatypes.Utf8String(_BCADD),
                        new org.web3j.abi.datatypes.Utf8String(_ADD)),
                Arrays.<TypeReference<?>>asList(new TypeReference<Uint8>() {}));
        return executeRemoteCallSingleValueReturn(function, BigInteger.class);
    }

    public static RemoteCall<BERAN3> deploy(Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        return deployRemoteCall(BERAN3.class, web3j, credentials, gasPrice, gasLimit, BINARY, "");
    }

    public static RemoteCall<BERAN3> deploy(Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        return deployRemoteCall(BERAN3.class, web3j, transactionManager, gasPrice, gasLimit, BINARY, "");
    }

    public static BERAN3 load(String contractAddress, Web3j web3j, Credentials credentials, BigInteger gasPrice, BigInteger gasLimit) {
        return new BERAN3(contractAddress, web3j, credentials, gasPrice, gasLimit);
    }

    public static BERAN3 load(String contractAddress, Web3j web3j, TransactionManager transactionManager, BigInteger gasPrice, BigInteger gasLimit) {
        return new BERAN3(contractAddress, web3j, transactionManager, gasPrice, gasLimit);
    }
}