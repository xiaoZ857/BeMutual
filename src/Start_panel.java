import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JButton;
import javax.swing.JLabel;
import java.awt.Font;
import javax.swing.JTextPane;
import java.awt.event.ActionListener;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.awt.event.ActionEvent;

public class Start_panel extends JFrame {

	
	private JPanel contentPane;
	static PrivateKey privateKey;
	static PublicKey publicKey;
	static String BCADD;
	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					Start_panel frame = new Start_panel();
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
	public Start_panel() {
		setTitle("Start");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 450, 363);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		
		
		JLabel lblNewLabel = new JLabel("BeMutual Demonstration");
		
		lblNewLabel.setBounds(145, 33, 210, 29);
		contentPane.add(lblNewLabel);
		
		JLabel lblNewLabel_1 = new JLabel("use 'bind' to upload your {BCADD & IP} binding");
		
		lblNewLabel_1.setBounds(85, 153, 276, 66);
		contentPane.add(lblNewLabel_1);

		JTextField textField = new JTextField();
		textField.setBounds(24, 229, 375, 66);
		contentPane.add(textField);
		textField.setColumns(10);
		
		JButton btnNewButton = new JButton("bind");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e){
				KeyPairGenerator keyPairGen = null;
				try {
					keyPairGen = KeyPairGenerator.getInstance("RSA");
				} catch (NoSuchAlgorithmException e1) {
					e1.printStackTrace();
				}
		        keyPairGen.initialize(512);
		        KeyPair keyPair = keyPairGen.generateKeyPair();
		        privateKey = (PrivateKey)keyPair.getPrivate();             
		        publicKey = (PublicKey)keyPair.getPublic();
		        BCADD = Register.generateBCADD(publicKey);
				textField.setText(BCADD);
				try {
					Register.upload(BCADD);
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				State_panel frame = new State_panel();
				frame.setVisible(true);
			}
		});
		
		btnNewButton.setBounds(118, 94, 193, 49);
		contentPane.add(btnNewButton);
	}
}
