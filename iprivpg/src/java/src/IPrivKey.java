/*
   Copyright (C) 1998-2007 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

package org.CyberPlat;

public class IPrivKey
{
	private int keyID;

	IPrivKey(int id)
	{
		keyID=id;
	}
	public int getKeyID()
	{
		return keyID;
	}
	public String signText(String text) throws Exception
	{
		return IPriv.signText(text,this);
	}
	public byte[] signByteArray(byte[] text) throws Exception
	{
		return IPriv.signByteArray(text,this);
	}
	public String verifyText(String text) throws Exception
	{
		return IPriv.verifyText(text,this);
	}
	public byte[] verifyByteArray(byte[] text) throws Exception
	{
		return IPriv.verifyByteArray(text,this);
	}
	public String signText2(String text) throws Exception
	{
		return IPriv.signText2(text,this);
	}
	public String verifyText2(String text,String sign) throws Exception
	{
		return IPriv.verifyText2(text,sign,this);
	}
	public String encryptText(String text) throws Exception
	{
		return IPriv.encryptText(text,this);
	}
	public String decryptText(String text) throws Exception
	{
		return IPriv.decryptText(text,this);
	}
	public void closeKey()
	{
		IPriv.closeKey(this);
	}
};
