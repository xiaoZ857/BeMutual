import java.awt.BorderLayout;
import java.awt.EventQueue;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import java.awt.Dialog.ModalExclusionType;
import java.awt.FlowLayout;
import javax.swing.JLabel;
import java.awt.Font;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.util.Map;
import java.awt.event.ActionEvent;
import java.awt.Color;
import javax.swing.JTextPane;
import javax.swing.JTextField;

public class State_panel extends JFrame {

	private JPanel contentPane;
	static byte[] key;
	String caller;
	boolean done = false;
	String BCADD;
	static InetAddress add;

	/**
	 * Launch the application.
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					State_panel frame = new State_panel();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
		talkpanel frame4 = new talkpanel(null);
		frame4.setVisible(true);
	}

	/**
	 * Create the frame.
	 */
	public State_panel() {
		setTitle("State");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 449, 306);
		contentPane = new JPanel();
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);
		
		JLabel lblNewLabel_2 = new JLabel("caller :");
		
		lblNewLabel_2.setBounds(34, 56, 68, 19);
		contentPane.add(lblNewLabel_2);
		
		
		JPanel panel_1 = new JPanel();
		panel_1.setBackground(Color.LIGHT_GRAY);
		panel_1.setBounds(5, 132, 426, 135);
		contentPane.add(panel_1);
		panel_1.setLayout(null);
		
		JLabel lblNewLabel_5 = new JLabel("enter BCADD to find others");
		lblNewLabel_5.setBounds(101, 47, 166, 15);
		panel_1.add(lblNewLabel_5);
		
		JLabel lblNewLabel_6 = new JLabel("BCADD : ");
		
		lblNewLabel_6.setBounds(21, 78, 81, 15);
		panel_1.add(lblNewLabel_6);
		
		
		JTextPane textPane_3 = new JTextPane();
		textPane_3.setBounds(101, 72, 166, 21);
		panel_1.add(textPane_3);
		
		JLabel lblNewLabel = new JLabel("Sender");
		
		lblNewLabel.setBounds(167, 10, 62, 27);
		panel_1.add(lblNewLabel);
		
		JTextPane textPane_3_3 = new JTextPane();
		textPane_3_3.setBounds(108, 54, 166, 21);
		contentPane.add(textPane_3_3);
		
		JLabel lblNewLabel_1 = new JLabel("Receiver");
		
		lblNewLabel_1.setBounds(162, 10, 82, 36);
		contentPane.add(lblNewLabel_1);
		
		JButton btnNewButton_1 = new JButton("receive");
		btnNewButton_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				Map<String, Object> res;
				try {
					res = Authentication.receiveSocket(Start_panel.publicKey, Start_panel.privateKey);
					key =  (byte[]) res.get("key");
					caller = (String)res.get("BCADD");
					add = (InetAddress)res.get("add");
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				if (key == null) {
					textPane_3_3.setText(caller+": Authentication failed");
				}else {
					textPane_3_3.setText(caller+": Authentication success");
					done = true;
				}
			}
		});
		btnNewButton_1.setBounds(303, 37, 97, 23);
		contentPane.add(btnNewButton_1);
		
		JButton btnNewButton = new JButton("connect");
		btnNewButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if(done == true) {
					done = false;
					textPane_3_3.setText("Connection success");
					talkpanel frame1;
					try {
						frame1 = new talkpanel(null);
						frame1.setVisible(true);
					} catch (IOException e1) {
						e1.printStackTrace();
					}
					
				}else {
					textPane_3_3.setText("Connection failed");
				}
				
			}
		});
		btnNewButton.setBounds(303, 70, 97, 23);
		contentPane.add(btnNewButton);

		JButton btnNewButton_3 = new JButton("find");
		btnNewButton_3.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				BCADD = textPane_3.getText();
				Map<String, Object> res;
				try {
					res = Authentication.sendSocket(Start_panel.publicKey, Start_panel.privateKey, BCADD);
					key =  (byte[]) res.get("key");
					add = (InetAddress)res.get("add");
					System.out.println("other add:"+State_panel.add.toString());
				} catch (Exception e1) {
					e1.printStackTrace();
				}
				if(key == null) {
					textPane_3.setText("Fail to find");
				}else {
					textPane_3.setText("Connection suceess");
					talkpanel frame4;
					try {
						frame4 = new talkpanel(null);
						frame4.setVisible(true);
					} catch (IOException e1) {
						e1.printStackTrace();
					}
					
				}
			}
		});
		btnNewButton_3.setBounds(305, 76, 97, 23);
		panel_1.add(btnNewButton_3);
	}
}
