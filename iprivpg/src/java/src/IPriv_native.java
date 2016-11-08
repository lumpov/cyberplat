/*
   Copyright (C) 1998-2007 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

package org.CyberPlat;

class IPriv_native
{
	static
	{
		System.loadLibrary("jiprivpg");
	}

	static protected native void setCodePage_native(String cp);
	static protected native int openSecretKey_native(String path,String passwd);
	static protected native int openSecretKeyMem_native(String key,String passwd);
	static protected native int openPublicKey_native(String path,int keyserial);
	static protected native int openPublicKeyMem_native(String key,int keyserial);
	static protected native String signText_native(int hkey,String text);
	static protected native byte[] signArray_native(int hkey,byte[] ba);
	static protected native String verifyText_native(int hkey,String text);
	static protected native byte[] verifyArray_native(int hkey,byte[] ba);
	static protected native String signText2_native(int hkey,String text);
	static protected native String verifyText2_native(int hkey,String text,String sign);
	static protected native String encryptText_native(int hkey,String text);
	static protected native String decryptText_native(int hkey,String text);
	static protected native int closeKey_native(int hkey);
	static protected native String getLang();
	static protected native int genKey_native(String keycard,int bits,String passwd,String sec,String pub);
	static protected native String[] genKeyMem_native(String userid,long keyserial,int bits,String passwd);
	static protected native void initialize_native();
	static protected native void done_native();
}
