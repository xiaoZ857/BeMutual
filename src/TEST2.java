
import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;

import java.awt.FlowLayout;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.BoxLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
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
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.awt.event.ActionEvent;
import java.awt.Font;
import javax.swing.DropMode;

import javax.swing.JScrollPane;

public class TEST2 extends JFrame {
    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
            .toCharArray();
    private static final int BASE_58 = ALPHABET.length;
    private static final int BASE_256 = 256;

    private static final int[] INDEXES = new int[128];
    static {
        for (int i = 0; i < INDEXES.length; i++) {
            INDEXES[i] = -1;
        }
        for (int i = 0; i < ALPHABET.length; i++) {
            INDEXES[ALPHABET[i]] = i;
        }
    }


    //base58 coding
    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }

        input = copyOfRange(input, 0, input.length);

        int zeroCount = 0;
        while (zeroCount < input.length && input[zeroCount] == 0) {
            ++zeroCount;
        }

        byte[] temp = new byte[input.length * 2];
        int j = temp.length;

        int startAt = zeroCount;
        while (startAt < input.length) {
            byte mod = divmod58(input, startAt);
            if (input[startAt] == 0) {
                ++startAt;
            }

            temp[--j] = (byte) ALPHABET[mod];
        }

        while (j < temp.length && temp[j] == ALPHABET[0]) {
            ++j;
        }

        while (--zeroCount >= 0) {
            temp[--j] = (byte) ALPHABET[0];
        }

        byte[] output = copyOfRange(temp, j, temp.length);
        return new String(output);
    }
    private static byte divmod58(byte[] number, int startAt) {
        int remainder = 0;
        for (int i = startAt; i < number.length; i++) {
            int digit256 = (int) number[i] & 0xFF;
            int temp = remainder * BASE_256 + digit256;
            number[i] = (byte) (temp / BASE_58);
            remainder = temp % BASE_58;
        }

        return (byte) remainder;
    }
    public static byte[] decode(String input) {
        if (input.length() == 0) {
            return new byte[0];
        }

        byte[] input58 = new byte[input.length()];

        for (int i = 0; i < input.length(); ++i) {
            char c = input.charAt(i);

            int digit58 = -1;
            if (c >= 0 && c < 128) {
                digit58 = INDEXES[c];
            }
            if (digit58 < 0) {
                throw new RuntimeException("Not a Base58 input: " + input);
            }

            input58[i] = (byte) digit58;
        }


        int zeroCount = 0;
        while (zeroCount < input58.length && input58[zeroCount] == 0) {
            ++zeroCount;
        }


        byte[] temp = new byte[input.length()];
        int j = temp.length;

        int startAt = zeroCount;
        while (startAt < input58.length) {
            byte mod = divmod256(input58, startAt);
            if (input58[startAt] == 0) {
                ++startAt;
            }

            temp[--j] = mod;
        }


        while (j < temp.length && temp[j] == 0) {
            ++j;
        }

        return copyOfRange(temp, j - zeroCount, temp.length);
    }
    private static byte divmod256(byte[] number58, int startAt) {
        int remainder = 0;
        for (int i = startAt; i < number58.length; i++) {
            int digit58 = (int) number58[i] & 0xFF;
            int temp = remainder * BASE_58 + digit58;
            number58[i] = (byte) (temp / BASE_256);
            remainder = temp % BASE_256;
        }

        return (byte) remainder;
    }

    private static byte[] copyOfRange(byte[] source, int from, int to) {
        byte[] range = new byte[to - from];
        System.arraycopy(source, from, range, 0, range.length);
        return range;
    }
    public static final String ALGORITHM = "AES/ECB/PKCS7Padding"; static{
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
    // integer to byte
    public static byte[] inttobyte(int i) {
        byte[] result = new byte[4];
        result[0] = (byte)((i >> 24) & 0xFF);
        result[1] = (byte)((i >> 16) & 0xFF);
        result[2] = (byte)((i >> 8) & 0xFF);
        result[3] = (byte)(i & 0xFF);
        return result;
    }
    // byte to integer
    public static int bytetoint(byte[] bytes) {
        int value=0;
        for(int i = 0; i < 4; i++) {
            int shift= (3-i) * 8;
            value +=(bytes[i] & 0xFF) << shift;
        }
        return value;
    }
    //private key encryption
    protected byte[] encrypt(PrivateKey privateKey,byte[] srcBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        if(privateKey!=null){
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            byte[] resultBytes = cipher.doFinal(srcBytes);
            return resultBytes;
        }
        return null;
    }
    //public key decryption
    protected byte[] decrypt(PublicKey publicKey,byte[] srcBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        if(publicKey!=null){
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] resultBytes = cipher.doFinal(srcBytes);
            return resultBytes;
        }
        return null;
    }

    //public key encryption
    protected byte[] encrypt1(PublicKey publicKey,byte[] srcBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        if(publicKey!=null){
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] resultBytes = cipher.doFinal(srcBytes);
            return resultBytes;
        }
        return null;
    }
    //private key decryption
    protected byte[] decrypt1(PrivateKey privateKey,byte[] srcBytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        if(privateKey!=null){
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] resultBytes = cipher.doFinal(srcBytes);
            return resultBytes;
        }
        return null;
    }

    private JPanel contentPane;
    private JTextField textField;
    private JTextField textField_1;
    JScrollPane jscrollPane;
    static String str = null;
    boolean isClick = false;
    String str1 = "hi";
    String str2 = "hi";
    String str3 = "hi";
    byte[] key = null;
    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    TEST2 frame = new TEST2();
                    frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    /**
     * Create the frame.
     */
    public TEST2() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,Exception{
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setBounds(100, 100, 587, 418);
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        setContentPane(contentPane);
        JLabel State = new JLabel("State");


        JLabel lblNewLabel = new JLabel("Message send to");

        textField = new JTextField();
        textField.setColumns(10);

        JLabel lblNewLabel_1 = new JLabel("Sending message");

        textField_1 = new JTextField();
        textField_1.setColumns(10);


        JButton btnNewButton_1 = new JButton("Send");

        JTextArea textArea_1 = new JTextArea();

        JLabel lblNewLabel_2 = new JLabel("Receiving message");

        JLabel lblNewLabel_3 = new JLabel("Node 2");

        JScrollPane scrollPane = new JScrollPane();
        GroupLayout gl_contentPane = new GroupLayout(contentPane);
        JTextArea textArea = new JTextArea();
        scrollPane.setViewportView(textArea);
        contentPane.setLayout(gl_contentPane);
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
        str1 = "Sender's ADD is:"+ip;
        System.out.println("Nonce is��" + nonce1);
        System.out.println("After decrypt��" + nonce2);
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
            str2 = "Authantication succeed";
            //send message
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            keyPairGen.initialize(512);
            // generate a key pair
            KeyPair keyPair = keyPairGen.generateKeyPair();
            // get private key
            PrivateKey privateKey = (PrivateKey)keyPair.getPrivate();
            // get public key
            PublicKey publicKey1 = (PublicKey)keyPair.getPublic();
            byte[] publicBT =publicKey1.getEncoded(); //��Կת��Ϊbytes
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
            str3 = "Receiver's ADD is:"+ ip1;
            TransactionReceipt recp = contract.upload(BC_ADD1,ip1).send();
            // generate new datagram
            DatagramPacket sendPacket = new DatagramPacket(results, results.length, address, port1);
            str = textField.getText();
            textArea.setText(str1+"\n"+str2+"\n"+str3+"\n"+"Do you want to make connection?");
            JButton btnNewButton_2 = new JButton("Connection");
            btnNewButton_2.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    isClick = true;
                    // send data
                    try {
                        recevieSocket.send(sendPacket);
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                    DatagramPacket receviePacket2 = new DatagramPacket(receiveByte, len);
                    // receive data
                    try {
                        recevieSocket.receive(receviePacket2);
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                    byte[] da2 = receviePacket2.getData();
                    byte[] da1 = new byte[64];
                    System.arraycopy(da2,0,da1,0,64);
                    try {
                        key = rsa.decrypt1(privateKey, da1);
                    } catch (InvalidKeyException e1) {
                        e1.printStackTrace();
                    } catch (NoSuchAlgorithmException e1) {
                        e1.printStackTrace();
                    } catch (NoSuchPaddingException e1) {
                        e1.printStackTrace();
                    } catch (IllegalBlockSizeException e1) {
                        e1.printStackTrace();
                    } catch (BadPaddingException e1) {
                        e1.printStackTrace();
                    }
                    System.out.println("Received seesion key");
                    textArea.setText("Do you want to make connection?"+"\n"+"You can send message.");

                }

            });
            btnNewButton_1.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String message = textField_1.getText();
                    textField_1.setText(null);
                    String Results1 = AESEncrypt.Aes256Encode(message, key);
                    byte[] results1 = null;
                    try {
                        results1 = Results1.getBytes("UTF-8");
                    } catch (UnsupportedEncodingException e1) {
                        e1.printStackTrace();
                    }
                    DatagramPacket sendPacket1 = new DatagramPacket(results1, results1.length, address, port1);
                    // send data
                    try {
                        recevieSocket.send(sendPacket1);
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                    DatagramPacket receviePacket1 = new DatagramPacket(receiveByte, len);
                    btnNewButton_1.setText("Receive");
                    // receive data
                    try {
                        recevieSocket.receive(receviePacket1);
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                    byte[] dat2 = receviePacket1.getData();
                    byte[] dat1 = new byte[24];
                    System.arraycopy(dat2,0,dat1,0,24);
                    String Result = null;
                    try {
                        Result = new String(dat1,"UTF-8");
                    } catch (UnsupportedEncodingException e1) {
                        e1.printStackTrace();
                    }
                    String Receiv = AESEncrypt.Aes256Decode(Result, key);
                    textArea_1.setText(Receiv);
                    if(isClick == true) {
                        btnNewButton_1.setText("Receive");
                        isClick = false;
                    }else {
                        btnNewButton_1.setText("Send");
                        isClick = true;
                    }

                }
            });



            gl_contentPane.setHorizontalGroup(
                    gl_contentPane.createParallelGroup(Alignment.LEADING)
                            .addGroup(gl_contentPane.createSequentialGroup()
                                    .addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
                                            .addGroup(gl_contentPane.createSequentialGroup()
                                                    .addGap(31)
                                                    .addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
                                                            .addComponent(lblNewLabel_1)
                                                            .addComponent(lblNewLabel_2)
                                                            .addComponent(State, GroupLayout.PREFERRED_SIZE, 76, GroupLayout.PREFERRED_SIZE)
                                                            .addComponent(lblNewLabel))
                                                    .addGap(26)
                                                    .addGroup(gl_contentPane.createParallelGroup(Alignment.TRAILING)
                                                            .addComponent(scrollPane, GroupLayout.DEFAULT_SIZE, 297, Short.MAX_VALUE)
                                                            .addComponent(textField, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 297, Short.MAX_VALUE)
                                                            .addComponent(textField_1, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 297, Short.MAX_VALUE)
                                                            .addComponent(textArea_1, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 297, Short.MAX_VALUE)))
                                            .addGroup(gl_contentPane.createSequentialGroup()
                                                    .addGap(237)
                                                    .addComponent(lblNewLabel_3)
                                                    .addGap(122)))
                                    .addPreferredGap(ComponentPlacement.RELATED)
                                    .addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING, false)
                                            .addComponent(btnNewButton_1, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                            .addComponent(btnNewButton_2, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                    .addContainerGap())
            );
            gl_contentPane.setVerticalGroup(
                    gl_contentPane.createParallelGroup(Alignment.LEADING)
                            .addGroup(gl_contentPane.createSequentialGroup()
                                    .addContainerGap()
                                    .addComponent(lblNewLabel_3)
                                    .addGroup(gl_contentPane.createParallelGroup(Alignment.LEADING)
                                            .addGroup(gl_contentPane.createSequentialGroup()
                                                    .addGap(46)
                                                    .addComponent(State, GroupLayout.PREFERRED_SIZE, 27, GroupLayout.PREFERRED_SIZE))
                                            .addGroup(gl_contentPane.createSequentialGroup()
                                                    .addGap(32)
                                                    .addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, 64, GroupLayout.PREFERRED_SIZE)))
                                    .addPreferredGap(ComponentPlacement.RELATED, 25, Short.MAX_VALUE)
                                    .addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
                                            .addComponent(lblNewLabel)
                                            .addComponent(textField, GroupLayout.PREFERRED_SIZE, 32, GroupLayout.PREFERRED_SIZE)
                                            .addComponent(btnNewButton_2))
                                    .addGap(44)
                                    .addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
                                            .addComponent(lblNewLabel_1)
                                            .addComponent(textField_1, GroupLayout.PREFERRED_SIZE, 34, GroupLayout.PREFERRED_SIZE)
                                            .addComponent(btnNewButton_1))
                                    .addGap(41)
                                    .addGroup(gl_contentPane.createParallelGroup(Alignment.BASELINE)
                                            .addComponent(textArea_1, GroupLayout.PREFERRED_SIZE, 57, GroupLayout.PREFERRED_SIZE)
                                            .addComponent(lblNewLabel_2))
                                    .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
            );

        }else {
            recevieSocket.close();
        }


    }
}
