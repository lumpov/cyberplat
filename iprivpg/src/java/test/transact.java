/*
 * Main.java
 *
 * Пример осуществляет проверку номера в платежной системе CyberPlat
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
    
    /** Инициализация объекта */
    public transact() {
    }
    
    /** Кодовая страница сервера */
    private static final String ENC="windows-1251";
    /** Код дилера */
    private static final String SD="17031";
    /** Код точки приема */
    private static final String AP="17032";
    /** Код точки оператора */
    private static final String OP="17034";
    /** Путь к ключам */
    private static final String KEYS="./test";
    /** Пароль от закрытого ключа */
    private static final String PASS="1111111111";
    /** Серийный номер банковского ключа */
    private static int BANK_KEY_SERIAL=64182;
    
    /** Закрытый ключ для формирования подписей */
    private IPrivKey sec=null;

    /** Открытый ключ банка для проверки подписей в ответах */
    private IPrivKey pub=null;
    

    /** Генерация номера сессии */
    String genSession()
    {
        String rc=new String();
        rc+="JAVA"+Calendar.getInstance().getTimeInMillis()/1000;
        return rc;
    }

    /** Ф-ция отправки запроса
     * @param url адрес
     * @param number номер телефона
     * @param amount сумма в рублях
     */
    String sendRequest(String url,String number,double amount) throws Exception
    {
        /* Формирование запроса */
        String req=
                "SD="+SD+"\r\n"+
                "AP="+AP+"\r\n"+
                "OP="+OP+"\r\n"+
                "SESSION="+genSession()+"\r\n"+
                "NUMBER="+number+"\r\n"+
                "AMOUNT="+amount+"\r\n";

        /* Кодирование запроса */
        req="inputmessage="+URLEncoder.encode(sec.signText(req));

        System.out.println("REQUEST: "+req);

        /* Соединение с сервером */
        URL u=new URL(url);
        URLConnection con=u.openConnection();
        con.setDoOutput(true);

//        con.connect();

        /* Отправка запроса */
        con.getOutputStream().write(req.getBytes());
        con.getOutputStream().close();

        /* Чтение ответа */
        BufferedReader in=new BufferedReader(new InputStreamReader(con.getInputStream(),ENC));
        char[] raw_resp=new char[1024];
        int raw_resp_len=in.read(raw_resp);
        StringBuffer s=new StringBuffer();
        s.append(raw_resp,0,raw_resp_len);
        String resp=s.toString();

        /* Проверка подписи сервера */
        resp=pub.verifyText(resp);


        System.out.println("RESPONSE:\r\n");
        System.out.println(resp);
        
        return resp;
    }
    
    /** Ф-ция закрытия ключей по окончании работы */
    void done()
    {
        if(sec!=null)
            sec.closeKey();
        if(pub!=null)
            pub.closeKey();
    }
    
    
    /**
     * @param args аргументы коммандной строки
     */
    public static void main(String[] args) {

        IPriv.Initialize();
        
        /* Создание главного объекта */
        transact m=new transact();
        
        /* Обязательно вызывать для указания кодовой страницы изначального документа */
        IPriv.setCodePage(ENC);
        
        try
        {
            /* Загрузка закрытого ключа для формирования подписей */
            m.sec=IPriv.openSecretKey(KEYS+"/secret.key",PASS);

            /* Загрузка открытого ключа банка (в боевой системе будет другой) */
            m.pub=IPriv.openPublicKey(KEYS+"/pubkeys.key",BANK_KEY_SERIAL);
            
            m.sendRequest("http://payment.cyberplat.ru/cgi-bin/es/es_pay_check.cgi","8888888888",12.5);
        }
        catch(Exception e)
        {
            System.out.println(e);
        }
        
        m.done();

        IPriv.Done();
    }
    
}
