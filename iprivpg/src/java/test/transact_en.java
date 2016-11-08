/*
 * Main.java
 *
 * request generation example
 * 
 */

import java.net.*;
import java.io.*;
import java.util.*;
import org.CyberPlat.*;

/**
 *
 * @author CyberPlat.Com
 */
public class transact {
    
    /** initialization */
    public transact() {
    }
    
    /** server code page */
    private static final String ENC="windows-1251";
    /** dealer code */
    private static final String SD="17031";
    /** point code */
    private static final String AP="17032";
    /** operator code */
    private static final String OP="17034";
    /** path to keys */
    private static final String KEYS="./test";
    /** secret key pass phrase */
    private static final String PASS="1111111111";
    /** bank public key serial number */
    private static int BANK_KEY_SERIAL=64182;
    
    /** secret key for signing */
    private IPrivKey sec=null;

    /** public key for signature verification */
    private IPrivKey pub=null;
    

    /** SESSION number generation */
    String genSession()
    {
        String rc=new String();
        rc+="JAVA"+Calendar.getInstance().getTimeInMillis()/1000;
        return rc;
    }

    /** send request function
     * @param url address
     * @param number phone number
     * @param amount to topup
     */
    String sendRequest(String url,String number,double amount) throws Exception
    {
        /* preparing request */
        String req=
                "SD="+SD+"\r\n"+
                "AP="+AP+"\r\n"+
                "OP="+OP+"\r\n"+
                "SESSION="+genSession()+"\r\n"+
                "NUMBER="+number+"\r\n"+
                "AMOUNT="+amount+"\r\n";

        /* signing and applying URL-encoding */
        req="inputmessage="+URLEncoder.encode(sec.signText(req));

        System.out.println("REQUEST: "+req);

        /* connect to server */
        URL u=new URL(url);
        URLConnection con=u.openConnection();
        con.setDoOutput(true);

//        con.connect();

        /* sending request */
        con.getOutputStream().write(req.getBytes());
        con.getOutputStream().close();

        /* reading response */
        BufferedReader in=new BufferedReader(new InputStreamReader(con.getInputStream(),ENC));
        char[] raw_resp=new char[2048];
        int raw_resp_len=in.read(raw_resp);
        StringBuffer s=new StringBuffer();
        s.append(raw_resp,0,raw_resp_len);
        String resp=s.toString();

        /* signature verification */
        resp=pub.verifyText(resp);


        System.out.println("RESPONSE:\r\n");
        System.out.println(resp);
        
        return resp;
    }
    
    /** free keys at program end */
    void done()
    {
        if(sec!=null)
            sec.closeKey();
        if(pub!=null)
            pub.closeKey();
    }
    
    
    /**
     * @param args
     */
    public static void main(String[] args) {
        
        transact m=new transact();
        IPriv.setCodePage(ENC);
        
        try
        {
            /* load secret key */
            m.sec=IPriv.openSecretKey(KEYS+"/secret.key",PASS);

            /* load public key */
            m.pub=IPriv.openPublicKey(KEYS+"/pubkeys.key",BANK_KEY_SERIAL);
            
            m.sendRequest("http://payment.cyberplat.ru/cgi-bin/es/es_pay_check.cgi","8888888888",12.5);
        }
        catch(Exception e)
        {
            System.out.println(e);
        }
        
        m.done();
    }
}
