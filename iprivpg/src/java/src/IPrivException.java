/*
   Copyright (C) 1998-2007 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

package org.CyberPlat;

public class IPrivException extends Exception
{
	public int code;

	IPrivException(int c)
	{
		code=c;
	}

	private String toString_ru()
	{
		switch(code)
		{
			case -1: return "Ошибка в аргументах";
			case -2: return "Ошибка выделения памяти";
			case -3: return "Неверный формат документа";
			case -4: return "Документ прочитан не до конца";
			case -5: return "Ошибка во внутренней структуре документа";
			case -6: return "Неизвестный алгоритм шифрования";
			case -7: return "Длина ключа не соответствует длине подписи";
			case -8: return "Неверная кодовая фраза закрытого ключа";
			case -9: return "Неверный тип документа";
			case -10: return "Ошибка ASCII кодирования документа";
			case -11: return "Ошибка ASCII декодирования документа";
			case -12: return "Неизвестный тип криптосредства";
			case -13: return "Криптосредство не готово";
			case -14: return "Вызов не поддерживается криптосредством";
			case -15: return "Файл не найден";
			case -16: return "Ошибка чтения файла";
			case -17: return "Ключ не может быть использован";
			case -18: return "Ошибка формирования подписи";
			case -19: return "Открытый ключ с таким серийным номером отсутствует";
			case -20: return "Подпись не соответствует содержимому документа";
			case -21: return "Ошибка создания файла";
			case -22: return "Ошибка записи в файл";
			case -23: return "Неверный формат карточки ключа";
			case -24: return "Ошибка генерации ключей";
			case -25: return "Ошибка шифрования";
			case -26: return "Ошибка дешифрации";
			case -70: return "Таблица ключей переполнена";
			case -71: return "Нет памяти";
			case -72: return "Неверный идентификатор ключа";
		}
		return "Общая ошибка";
	}

	private String toString_en()
	{
		switch(code)
		{
			case -1: return "Argument error";
			case -2: return "Memory allocation error";
			case -3: return "Wrong document format";
			case -4: return "Partially read document";
			case -5: return "Internal document error";
			case -6: return "Unknown cipher algorithm";
			case -7: return "Key length mismatch sign length";
			case -8: return "Wrong key phrase";
			case -9: return "Wrong document type";
			case -10: return "ASCII encoding error";
			case -11: return "ASCII decoding error";
			case -12: return "Unknown crypto provider";
			case -13: return "Crypto provader not ready";
			case -14: return "Unsupported call to crypto provider";
			case -15: return "File not found";
			case -16: return "File read error";
			case -17: return "Key cannot be used";
			case -18: return "Sign creation error";
			case -19: return "Missing open key with specified serial number";
			case -20: return "Sign mismatch document content";
			case -21: return "File creation error";
			case -22: return "File write error";
			case -23: return "Wrong key card format";
			case -24: return "Key generation error";
			case -25: return "Encryption error";
			case -26: return "Decryption error";
			case -70: return "Key table overflow";
			case -71: return "Out of memory";
			case -72: return "Invalid keyid";
			case -73: return "Genkey fail";
		}
		return "General fault";
	}

	public String toString()
	{
	    String rc;

	    if(IPriv.getLang().equalsIgnoreCase("ru"))
		rc=toString_ru();
	    else
		rc=toString_en();
	
	    return rc+" ("+code+")";
	}

}
