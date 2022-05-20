import javax.swing.*;



import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;





public class talkpanel extends JFrame implements ActionListener {
    Menu ms;
    JButton sendBt;
    JButton startBt;
    JTextField inputFiled;
    JTextArea chatContent;

    public talkpanel( final Menu ms ) throws IOException {
    	
        setAlwaysOnTop(true);
        this.setLayout(new BorderLayout());
        chatContent=new JTextArea(12,34);
        JScrollPane showPanel=new JScrollPane(chatContent);
        chatContent.setEditable(false);
        JPanel inputPanel=new JPanel();
        inputFiled=new JTextField(20);
        sendBt=new JButton("send");

        sendBt.addActionListener(e -> {
            String content=inputFiled.getText();
            if(content !=null && !content.trim().equals("")){
            	
                chatContent.append("local:"+content+"\n");
                String Results1 = crypto.Aes256Encode(content, State_panel.key);
                byte[] results1;
    			try {
    				DatagramSocket sendSocket = new DatagramSocket();
    				results1 = Results1.getBytes("UTF-8");
    				System.out.println("other add:"+State_panel.add.toString());
    				String ip = State_panel.add.toString().substring(1,State_panel.add.toString().length());
    				System.out.println("real add:"+ip);
    				InetAddress add = InetAddress.getByName(ip);
    				DatagramPacket sendPacket1 = new DatagramPacket(results1, results1.length, add, 12345);
    				// send data
    				sendSocket.send(sendPacket1);
    				sendSocket.close();
    			} catch (IOException e1) {
    				e1.printStackTrace();
    			}
            }
            else{
                chatContent.append("please send something!"+"\n");
            }
            inputFiled.setText("");
            
			
        });
        startBt=new JButton("receive");
        startBt.addActionListener(e -> {
        	    
        	    byte[] recevieByte = new byte[1024];
        		int len = recevieByte.length;
        		DatagramPacket receviePacket1 = new DatagramPacket(recevieByte, len);
    			try {
    				DatagramSocket receSocket = new DatagramSocket(12345);
					receSocket.receive(receviePacket1);
					System.out.println("Received");
					receSocket.close();
				} catch (IOException e1) {

					e1.printStackTrace();
				}
    			byte[] dat2 = receviePacket1.getData();
    			byte[] dat1 = new byte[24];
    			System.arraycopy(dat2,0,dat1,0,24);
    			String Result;
				try {
					Result = new String(dat1,"UTF-8");
					String Receiv = crypto.Aes256Decode(Result, State_panel.key);
	    			chatContent.append("Other:"+Receiv+"\n");
				} catch (UnsupportedEncodingException e1) {
					e1.printStackTrace();
				}
        });
        Label label=new Label("type here");
        inputPanel.add(label);
        inputPanel.add(inputFiled);
        inputPanel.add(sendBt);
        inputPanel.add(startBt);

        this.add(showPanel,BorderLayout.CENTER);
        this.add(inputPanel,BorderLayout.SOUTH);
        this.setTitle("ChatPanel");
        this.setSize(500, 500);
        
    }

    @Override
    public void actionPerformed(ActionEvent e) {

    }
}