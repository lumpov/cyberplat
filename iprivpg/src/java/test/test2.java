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
            String keys[]=IPriv.genKeyMem("api17032",12345,512,"1111111111");

	    sec=IPriv.openSecretKeyMem(keys[0],"1111111111");
	    pub=IPriv.openPublicKeyMem(keys[1],0);

	    String s1=sec.signText("Привет");
	    System.out.println("\""+s1+"\"");

	    String s2=pub.verifyText(s1);
	    System.out.println("\""+s2+"\"");
	    
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
