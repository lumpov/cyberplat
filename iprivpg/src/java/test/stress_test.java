import org.CyberPlat.*;

class stress_test
{
    public static void main(String args[])
    {
	try
	{
	    for(;;)
	    {
	        try
		{

		    IPrivKey sec_1=IPriv.openSecretKey("test/secret.key","1111111111");
		    IPrivKey pub_1=IPriv.openPublicKey("test/pubkeys.key",17033);

		    String s1_1=sec_1.signText("Привет");

		    String s2_1=pub_1.verifyText(s1_1);

		    String s3_1=pub_1.encryptText("Привет");

		    String s4_1=sec_1.decryptText(s3_1);
	    
		    sec_1.closeKey();
		    pub_1.closeKey();

//		    IPrivKey xxx=IPriv.openSecretKey("test/secret.key","111111111");

		}
	        catch(Exception e)
		{
		    System.out.println(e.toString());
		}
	    }
	    
	}
	catch(Exception e)
	{
	    System.out.println(e.toString());	    
	}
    }
}
