/*
   Copyright (C) 1998-2007 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

package org.CyberPlat;

public class IPriv extends IPriv_native
{
	private static String lang;
	
	static
	{
	    lang=IPriv_native.getLang();
	}
	
	public static String getLang()
	{
	    return lang;
	}

	public static void setCodePage(String cp)
	{
		setCodePage_native(cp);
	}
	public static IPrivKey openSecretKey(String path,String passwd) throws Exception
	{
		return new IPrivKey(openSecretKey_native(path,passwd));
	}
	public static IPrivKey openSecretKeyMem(String key,String passwd) throws Exception
	{
		return new IPrivKey(openSecretKeyMem_native(key,passwd));
	}
	public static IPrivKey openPublicKey(String path,int keyserial) throws Exception
	{
		return new IPrivKey(openPublicKey_native(path,keyserial));
	}
	public static IPrivKey openPublicKeyMem(String key,int keyserial) throws Exception
	{
		return new IPrivKey(openPublicKeyMem_native(key,keyserial));
	}
	public static void closeKey(IPrivKey key)
	{
		closeKey_native(key.getKeyID());
	}
	public static String signText(String text,IPrivKey key) throws Exception
	{
		return signText_native(key.getKeyID(),text);
	}
	public static byte[] signByteArray(byte[] text,IPrivKey key) throws Exception
	{
		return signArray_native(key.getKeyID(),text);
	}
	public static String verifyText(String text,IPrivKey key) throws Exception
	{
		return verifyText_native(key.getKeyID(),text);
	}
	public static byte[] verifyByteArray(byte[] text,IPrivKey key) throws Exception
	{
		return verifyArray_native(key.getKeyID(),text);
	}
	public static String signText2(String text,IPrivKey key) throws Exception
	{
		return signText2_native(key.getKeyID(),text);
	}
	public static String verifyText2(String text,String sign,IPrivKey key) throws Exception
	{
		return verifyText2_native(key.getKeyID(),text,sign);
	}
	public static String encryptText(String text,IPrivKey key) throws Exception
	{
		return encryptText_native(key.getKeyID(),text);
	}
	public static String decryptText(String text,IPrivKey key) throws Exception
	{
		return decryptText_native(key.getKeyID(),text);
	}

        public static int genKey(String keycard,int bits,String passwd,String sec,String pub)
        {
            return genKey_native(keycard,bits,passwd,sec,pub);
        }

        public static String[] genKeyMem(String userid,long keyserial,int bits,String passwd)
        {
            return genKeyMem_native(userid,keyserial,bits,passwd);
        }

	public static void Initialize()
	{
	        initialize_native();
	}
	public static void Done()
	{
	        done_native();
	}
};
