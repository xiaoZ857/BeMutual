import java.awt.BorderLayout;
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
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.awt.EventQueue;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.FlowLayout;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.BoxLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.JLabel;
import javax.swing.JTextArea;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.awt.event.ActionEvent;
import java.awt.Font;
import javax.swing.DropMode;
import javax.swing.JScrollPane;


public class TEST1 extends  JFrame{
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
    byte[] key = null;
    String str1 = "hi";
    String str2 = "hi";
    String str3 = "hi";

    /**
     * Launch the application.
     */
    public static void main(String[] args) {
        EventQueue.invokeLater(new Runnable() {
            public void run() {
                try {
                    TEST1 frame = new TEST1();
                    frame.setVisible(true);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });

    }

    /**
     * Create the frame.
     * @throws Exception
     */
    public TEST1() throws Exception {
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


        JButton btnNewButton_1 = new JButton("Receive");

        JTextArea textArea_1 = new JTextArea();

        JLabel lblNewLabel_2 = new JLabel("Receiving message");

        JLabel lblNewLabel_3 = new JLabel("Node 1");
        lblNewLabel_3.setFont(new Font("����", Font.PLAIN, 20));

        JScrollPane scrollPane = new JScrollPane();
        GroupLayout gl_contentPane = new GroupLayout(contentPane);
        JTextArea textArea = new JTextArea();
        scrollPane.setViewportView(textArea);
        contentPane.setLayout(gl_contentPane);
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
        str1 = "Sender's ADD is:"+ ip1;
        TransactionReceipt recp = contract.upload(BC_ADD,ip1).send();
        JButton btnNewButton_2 = new JButton("Connection");
        btnNewButton_2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                str = textField.getText();

                isClick = true;
                int port = 12345;
                try {
                    InetAddress address = InetAddress.getByName(str);
                } catch (UnknownHostException e4) {
                    e4.printStackTrace();
                }
                byte[] results = new byte[162];
                System.arraycopy(publicBT, 0, results, 0, len1);
                System.arraycopy(srcBytes, 0, results, len1-1, len2);
                System.arraycopy(resultBytes, 0, results, len1+len2-1, len3);
                DatagramPacket sendPacket = new DatagramPacket(results, results.length, address, port);
                // send data
                try {
                    sendSocket.send(sendPacket);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
                byte[] recevieByte = new byte[1024];
                int len = recevieByte.length;
                DatagramPacket receivePacket = new DatagramPacket(recevieByte, len);
                // receive data
                try {
                    sendSocket.receive(receivePacket);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
                byte[] dat = receivePacket.getData();
                byte[] data1 = new byte[94];
                System.arraycopy(dat, 0, data1, 0, 94);
                data1[93] = 1;
                byte[] data2 = new byte[4];
                System.arraycopy(dat, 93, data2, 0, 4);
                byte[] data3 = new byte[64];
                System.arraycopy(dat, 97, data3, 0, 64);
                // get public key
                KeyFactory kf = null;
                try {
                    kf = KeyFactory.getInstance("RSA");
                } catch (NoSuchAlgorithmException e1) {
                    e1.printStackTrace();
                }
                PublicKey publickey1 = null;
                try {
                    publickey1 = kf.generatePublic(new X509EncodedKeySpec(data1));
                } catch (InvalidKeySpecException e1) {
                    e1.printStackTrace();
                }
                byte[] publicByte =publickey1.getEncoded();
                // encrypt by public key
                byte[] decBytes = null;
                try {
                    decBytes = rsa.decrypt(publickey1, data3);
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
                str3 = "Receiver's ADD is:"+ ip;
                BigInteger be = null;
                try {
                    be = contract.call(BC_ADD1,ip).send();
                } catch (Exception e1) {
                    e1.printStackTrace();
                }
                System.out.println(be);
                int a =Integer.valueOf(be.toString());
                if(nonce1==nonce2 && a==1) {
                    System.out.println("Authantication succeed");
                    str2 = "Authantication succeed";
                    // generate session key
                    String aesKey = "66669999666699996666999966669999";
                    key = aesKey.getBytes();
                    byte[] results2 = null;
                    try {
                        results2 = rsa.encrypt1(publickey1, key);
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
                    DatagramPacket sendPacket2 = new DatagramPacket(results2, results2.length, address, port);
                    // send data
                    try {
                        sendSocket.send(sendPacket2);
                    } catch (IOException e3) {
                        e3.printStackTrace();
                    }
                    textArea.setText(str1+"\n"+str2+"\n"+str3+"\n");

                }else {
                    // close source
                    sendSocket.close();

                }
            }
        });
        btnNewButton_1.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                byte[] recevieByte = new byte[1024];
                int len = recevieByte.length;
                // receive data
                DatagramPacket receviePacket1 = new DatagramPacket(recevieByte, len);
                try {
                    sendSocket.receive(receviePacket1);
                } catch (IOException e2) {
                    e2.printStackTrace();
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
                String result1 = textField_1.getText();
                textField_1.setText(null);
                String Results1 = AESEncrypt.Aes256Encode(result1, key);
                byte[] results1 = null;
                try {
                    results1 = Results1.getBytes("UTF-8");
                } catch (UnsupportedEncodingException e1) {
                    e1.printStackTrace();
                }
                DatagramPacket sendPacket1 = new DatagramPacket(results1, results1.length, address, 12345);
                // send data
                try {
                    sendSocket.send(sendPacket1);
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
                if(isClick == true) {
                    btnNewButton_1.setText("Send");
                    isClick = false;
                }else {
                    btnNewButton_1.setText("Receive");
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





    }
}