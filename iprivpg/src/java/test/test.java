import org.CyberPlat.*;

class test
{
    public static void main(String args[])
    {
        IPriv.Initialize();

	IPrivKey sec=null;
	IPrivKey pub=null;
	try
	{
	    sec=IPriv.openSecretKey("test/secret.key","1111111111");
	    pub=IPriv.openPublicKey("test/pubkeys.key",17033);

	    String s1=sec.signText("Hello, world!");
	    System.out.println("\""+s1+"\"");

	    String s2=pub.verifyText(s1);
	    System.out.println("\""+s2+"\"");
	    
	    String s3=pub.encryptText("Hello, world!");
	    System.out.println("\""+s3+"\"");

	    String s4=sec.decryptText(s3);
	    System.out.println("\""+s4+"\"");

	    String s5=sec.signText2("Hello, world!");
	    System.out.println("\""+s5+"\"");

	    String s6=pub.verifyText2("Hello, world!",s5);
	    System.out.println("\""+s6+"\"");

//            IPriv.genKey("test/Kapi17032.dat",512,"1111111111","test/secret_new.key","test/pubkeys_new.key");
/*
            String keys[]=IPriv.genKeyMem("api17032",12345,512,"1111111111");
            System.out.println(keys[0]);
            System.out.println(keys[1]);
*/
	    
	    String ss7=new String("ByteArray");
            String s7=new String(sec.signByteArray(ss7.getBytes("cp1251")),"cp1251");
	    System.out.println("\""+s7+"\"");

            String s8=new String(pub.verifyByteArray(s7.getBytes("cp1251")),"cp1251");
	    System.out.println("\""+s8+"\"");
	}
	catch(Exception e)
	{
	    System.out.println(e.toString());	    
	}
	
	if(sec!=null)
	    IPriv.closeKey(sec);
	if(pub!=null)
	    IPriv.closeKey(pub);

        IPriv.Done();

    }
}
