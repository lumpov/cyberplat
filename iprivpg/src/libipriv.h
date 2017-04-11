/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/


#ifndef __LIBIPRIV_H
#define __LIBIPRIV_H

// Коды ошибок
#define CRYPT_ERR_BAD_ARGS		-1	// Ошибка в аргументах
#define CRYPT_ERR_OUT_OF_MEMORY		-2	// Ошибка выделения памяти
#define	CRYPT_ERR_INVALID_FORMAT	-3	// Неверный формат документа
#define CRYPT_ERR_NO_DATA_FOUND		-4	// Документ прочитан не до конца
#define CRYPT_ERR_INVALID_PACKET_FORMAT	-5	// Ошибка во внутренней структуре документа
#define CRYPT_ERR_UNKNOWN_ALG		-6	// Неизвестный алгоритм шифрования
#define CRYPT_ERR_INVALID_KEYLEN	-7	// Длина ключа не соответствует длине подписи
#define CRYPT_ERR_INVALID_PASSWD	-8	// Неверная кодовая фраза закрытого ключа
#define CRYPT_ERR_DOCTYPE		-9	// Неверный тип документа
#define CRYPT_ERR_RADIX_DECODE		-10	// Ошибка ASCII кодирования документа
#define CRYPT_ERR_RADIX_ENCODE		-11	// Ошибка ASCII декодирования документа
#define CRYPT_ERR_INVALID_ENG		-12	// Неизвестный тип криптосредства
#define CRYPT_ERR_ENG_NOT_READY		-13	// Криптосредство не готово
#define CRYPT_ERR_NOT_SUPPORT		-14	// Вызов не поддерживается криптосредством
#define CRYPT_ERR_FILE_NOT_FOUND	-15	// Файл не найден
#define CRYPT_ERR_CANT_READ_FILE	-16	// Ошибка чтения файла
#define CRYPT_ERR_INVALID_KEY		-17	// Ключ не может быть использован
#define CRYPT_ERR_SEC_ENC		-18	// Ошибка формирования подписи
#define CRYPT_ERR_PUB_KEY_NOT_FOUND	-19	// Открытый ключ с таким серийным номером отсутствует
#define CRYPT_ERR_VERIFY		-20	// Подпись не соответствует содержимому документа
#define CRYPT_ERR_CREATE_FILE		-21	// Ошибка создания файла
#define CRYPT_ERR_CANT_WRITE_FILE	-22	// Ошибка записи в файл
#define CRYPT_ERR_INVALID_KEYCARD	-23	// Неверный формат карточки ключа
#define CRYPT_ERR_GENKEY		-24	// Ошибка генерации ключей
#define CRYPT_ERR_PUB_ENC		-25	// Ошибка шифрования
#define CRYPT_ERR_SEC_DEC		-26	// Ошибка дешифрации
#define CRYPT_ERR_UNKNOWN_SENDER	-27	// Отправитель неопределен

// Типы криптосредств
#define IPRIV_ENGINE_RSAREF         0	// Библиотека RSAREF
#define IPRIV_ENGINE_OPENSSL        1	// Библиотека OpenSSL
#define IPRIV_ENGINE_PKCS11	        2	// Интерфейс PKCS11 (частный случай eToken)
#define IPRIV_ENGINE_WINCRYPT       3	// Интерфейс Microsoft Windows CryptoAPI
#define IPRIV_ENGINE_SENSELOCK      4	// Интерфейс SenseLock
#define IPRIV_ENGINE_PKCS11_RUTOKEN 5	// Интерфейс PKCS11 (частный случай RuToken)

#define IPRIV_ENGINE_DEFAULT		IPRIV_ENGINE_RSAREF
#define IPRIV_DEFAULT_ENGINE		IPRIV_ENGINE_DEFAULT

// Максимальное количество поддерживаемых криптосредств
#define IPRIV_MAX_ENG_NUM		6

// Типы запросов к криптосредствам (используется при вызове Crypt_Ctrl)
#define IPRIV_ENGCMD_IS_READY			0	// in: none, retval: 1-ready, 0 - not ready
#define IPRIV_ENGCMD_GET_ERROR			1	// in: none, retval: errcode
#define IPRIV_ENGCMD_SET_PIN			2	// in: const char* null-terminated pin code, retval: 0-success
#define IPRIV_ENGCMD_SET_PKCS11_LIB		3	// in: static const char* null-terminated path to library, retval: 0-success
#define IPRIV_ENGCMD_GET_PKCS11_SLOTS_NUM	4	// in: none, retval - slots num or 0
#define IPRIV_ENGCMD_GET_PKCS11_SLOT_NAME	5	// in: int slot index, char* dst, int ndst, retval - string length
#define IPRIV_ENGCMD_SET_PKCS11_SLOT		6	// in: int slot index (from 0), retval - 0-success
#define IPRIV_ENGCMD_ENUM_PKCS11_KEYS		7	// in: IPRIV_KEY* array, int array max size, retval - keys num
#define IPRIV_ENGCMD_ENUM_PKCS11_PUBKEYS	8	// in: IPRIV_KEY* array, int array max size, retval - keys num
#define IPRIV_ENGCMD_PEM_EXPORT			9	// in: IPRIV_KEY* key, char *passphrase, char *dst, int ndst, retval: 0 success
#define IPRIV_ENGCMD_PEM_IMPORT			10	// in: IPRIV_KEY* key, char *passphrase, char *src, int nsrc, retval: 0 success
#define IPRIV_ENGCMD_GET_KEY_LENGTH		11	// in: IPRIV_KEY* key, retval: key length
#define IPRIV_ENGCMD_SET_PIN2			12	// in: const char* null-terminated pin code, retval: 0-success
#define IPRIV_ENGCMD_PKCS11_DELKEY		13	// in: unsigned long keyserial, retval: 0 - success
#define IPRIV_ENGCMD_PKCS11_FORMAT_SLOT	14	// in: int slot index, retval: 0 - success
#define IPRIV_ENGCMD_PKCS11_GET_DATA	15	// in: const char * name, char * data, unsigned maxDataSize, retval: > 0 - filesize
#define IPRIV_ENGCMD_PKCS11_SET_DATA	16	// in: const char * name, const char * data, unsigned dataSize, retval: 0 - success
#define IPRIV_ENGCMD_PKCS11_REMOVE_DATA	17	// in: const char * name, retval: 0 - success

// Типы ключей
#define IPRIV_KEY_TYPE_RSA_SECRET	1
#define IPRIV_KEY_TYPE_RSA_PUBLIC	2

// Алгоритмы свертки
#define IPRIV_ALG_MD5           1
#define IPRIV_ALG_SHA256        2

// Максимальная длина кода покупателя
#define MAX_USERID_LENGTH		20

// Проверка возвращаемого значения на наличие ошибок
#define CRYPT_IS_ERROR(RC)	(RC < 0)
#define CRYPT_IS_SUCCESS(RC)	(RC >= 0)


#ifdef _WIN32
#define	IPRIVAPI	__stdcall
#else
#define	IPRIVAPI
#endif


// Структура ключа
typedef struct
{
	short eng;				// Тип криптосредства
	short type;				// Тип ключа
	unsigned long keyserial;		// Серийный номер ключа
	char userid[24];			// Код покупателя (минимум MAX_USERID_LENGTH+1)
	void* key;				// Специфические для криптосредства данные
	unsigned int flags;
	unsigned long timestamp;
} IPRIV_KEY;


// Функция обратного вызова для загрузки открытого ключа по серийному номеру.
// Должна возвращать 0 в случае успеха или код ошибки.
typedef int (*Crypt_FindPublicKey_t)(unsigned long keyserial,IPRIV_KEY* key,char* info,int info_len);

// ************************
// Интерфейс библиотеки   *
// ************************

#ifdef __cplusplus
extern "C" {
#endif

// Инициализация библиотеки.
// Должна выполняться только один раз при запуски приложения (в основном потоке).
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_Initialize(void);


// Произвольный запрос к криптопровайдеру.
// Необходимо для обращения к нестандартным функциям криптопровайдера.
// Например, установка пин-кода для доступа к электронному ключу eToken.
// eng: входной, тип криптопровайдера
// cmd: входной, тип запроса
// Возвращает: зависит от типа запроса
int Crypt_Ctrl(int eng,int cmd,...);
int IPRIVAPI Crypt_Ctrl_Null(int eng,int cmd);
int IPRIVAPI Crypt_Ctrl_String(int eng,int cmd,const char* arg);
int IPRIVAPI Crypt_Ctrl_Int(int eng,int cmd,int arg);
int IPRIVAPI Crypt_Ctrl_Ptr(int eng,int cmd,void* arg);

// Формирование карточки ключа в памяти (Crypt_GenKeyCard) или в файле (Crypt_GenKeyCardToFile).
// dst: выходной, буфер для приема тела карточки ключа
// ndst: входной, максимальная длина приемного буфера
// path: входной, путь к файлу для карточки ключа
// userid: входной, код покупателя
// keyserial: входной, серийный номер ключа
// Возвращает: длина тела карточки или код ошибки
int IPRIVAPI Crypt_GenKeyCard(char* dst,int ndst,const char* userid,unsigned long keyserial);
int IPRIVAPI Crypt_GenKeyCardToFile(const char* path,const char* userid,unsigned long keyserial);

// Чтение карточки ключа
// path: входной, путь к файлу для карточки ключа
// keyserial: выходной, серийный номер ключа
// userid: выходной, код покупателя
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_ReadKeyCardFromFile(const char* path,unsigned long* keyserial,char* userid);

// Генерация пары ключей (закрытый/открытый) на основе карточки ключа.
// eng: входной, тип криптопровайдера
// src: входной, буфер с телом карточки ключа
// nsrc: входной, длина буфера, -1 - считается сама (должен быть нуль-терминатор)
// keycardpath: входной, путь к файлу с карточкой ключа
// sec: выходной, закрытый ключ
// pub: выходной, открытый ключ
// bits: входной, длина ключа в битах
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_GenKey(int eng,const char* src,int nsrc,IPRIV_KEY* sec,IPRIV_KEY* pub,int bits);
int IPRIVAPI Crypt_GenKeyFromFile(int eng,const char* keycardpath,IPRIV_KEY* sec,IPRIV_KEY* pub,int bits);
int IPRIVAPI Crypt_GenKey2(int eng,unsigned long keyserial,const char* userid,IPRIV_KEY* sec,IPRIV_KEY* pub,int bits);

// Загрузка закрытого ключа из буфера в памяти (Crypt_OpenSecretKey), из файла (Crypt_OpenSecretKeyFromFile)
// или из внутреннего хранилища криптопровайдера (Crypt_OpenSecretKeyFromStore). Crypt_OpenSecretKey2 грузит ключ
// из буфера без заголовков (чистое тело ключа в base64).
// eng: входной, тип криптопровайдера
// src: входной, буфер с телом закрытого ключа
// nsrc: входной, длина буфера, -1 - считается сама (должен быть нуль-терминатор)
// path: входной, путь к файлу с закрытым ключом
// passwd: входной, кодовая фраза для расшифровки закрытого ключа
// keyserial: входной, серийный номер закрытого ключа
// key: выходной, закрытый ключ
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_OpenSecretKey(int eng,const char* src,int nsrc,const char* passwd,IPRIV_KEY* key);
int IPRIVAPI Crypt_OpenSecretKey2(int eng,const char* src,int nsrc,const char* passwd,IPRIV_KEY* key);
int IPRIVAPI Crypt_OpenSecretKeyFromFile(int eng,const char* path,const char* passwd,IPRIV_KEY* key);
int IPRIVAPI Crypt_OpenSecretKeyFromStore(int eng,unsigned long keyserial,IPRIV_KEY* key);

// Загрузка открытого ключа из буфера в памяти (Crypt_OpenPublicKey), из файла (Crypt_OpenPublicKeyFromFile)
// или из внутреннего хранилища криптопровайдера (Crypt_OpenPublicKeyFromStore). Crypt_OpenPublicKey2 грузит ключ
// из буфера без заголовков и подписи (чистое тело ключа в base64).
// eng: входной, тип криптопровайдера
// src: входной, буфер с телом открытого ключа
// nsrc: входной, длина буфера, -1 - считается сама (должен быть нуль-терминатор)
// path: входной, путь к файлу с открытыми ключами
// keyserial: входной, серийный номер открытого ключа
// key: выходной, открытый ключ
// cakey: входной, может быть 0, открытый ключ для проверки подписи ключа
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_OpenPublicKey(int eng,const char* src,int nsrc,unsigned long keyserial,IPRIV_KEY* key,IPRIV_KEY* cakey);
int IPRIVAPI Crypt_OpenPublicKey2(int eng,const char* src,int nsrc,IPRIV_KEY* key);
int IPRIVAPI Crypt_OpenPublicKeyFromFile(int eng,const char* path,unsigned long keyserial,IPRIV_KEY* key,IPRIV_KEY* cakey);
int IPRIVAPI Crypt_OpenPublicKeyFromStore(int eng,unsigned long keyserial,IPRIV_KEY* key);

// Экспорт закрытого ключа (может не поддерживаться криптопровайдером).
// dst: выходной, буфер для приема закрытого ключа
// ndst: входной, максимальная длина приемного буфера
// path: входной, путь к файлу для закрытого ключа
// passwd: входной, кодовая фраза для шифрования закрытого ключа
// key: входной, закрытый ключ
// Возвращает: длина тела ключа или код ошибки
int IPRIVAPI Crypt_ExportSecretKey(char* dst,int ndst,const char* passwd,IPRIV_KEY* key);
int IPRIVAPI Crypt_ExportSecretKeyToFile(const char* path,const char* passwd,IPRIV_KEY* key);

// Экспорт открытого ключа.
// dst: выходной, буфер для приема открытого ключа
// ndst: входной, максимальная длина приемного буфера
// path: входной, путь к файлу с открытыми ключами
// key: входной, открытый ключ
// cakey: входной, может быть 0, закрытый ключ для формирования подписи открытого ключа
// Возвращает: длина тела ключа или код ошибки
int IPRIVAPI Crypt_ExportPublicKey(char* dst,int ndst,IPRIV_KEY* key,IPRIV_KEY* cakey);
int IPRIVAPI Crypt_ExportPublicKeyToFile(const char* path,IPRIV_KEY* key,IPRIV_KEY* cakey);

// Импорт закрытого ключа во внутреннее хранилище криптопровайдера (может не поддерживаться).
// Например, импорт закрытого ключа покупателя в электронный ключ eToken.
// eng: входной, тип криптопровайдера
// src: входной, буфер с телом закрытого ключа
// nsrc: входной, длина буфера, -1 - считается сама (должен быть нуль-терминатор)
// path: входной, путь к файлу с закрытым ключом
// passwd: входной, кодовая фраза для расшифровки закрытого ключа
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_ImportSecretKey(int eng,const char* src,int nsrc,const char* passwd);
int IPRIVAPI Crypt_ImportSecretKeyFromFile(int eng,const char* path,const char* passwd);

// Импорт открытого ключа во внутреннее хранилище криптопровайдера (может не поддерживаться).
// Например, импорт открытого ключа банка в электронный ключ eToken.
// eng: входной, тип криптопровайдера
// src: входной, буфер с телом открытого ключа
// nsrc: входной, длина буфера, -1 - считается сама (должен быть нуль-терминатор)
// path: входной, путь к файлу с открытыми ключами
// keyserial: входной, серийный номер открытого ключа
// cakey: входной, может быть 0, открытый ключ для проверки подписи ключа
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_ImportPublicKey(int eng,const char* src,int nsrc,unsigned long keyserial,IPRIV_KEY* cakey);
int IPRIVAPI Crypt_ImportPublicKeyFromFile(int eng,const char* path,unsigned long keyserial,IPRIV_KEY* cakey);

// Выбор алгоритма свертки для последующих вызовов Crypt_Sign*
int IPRIVAPI Crypt_SetHashAlg(int alg);

// Формирование подписи сообщения.
// src: входной, буфер с телом сообщения
// nsrc: длина сообщения, -1 - считается сама (должен быть нуль-терминатор)
// dst: выходной, буфер для приема тела подписанного сообщения
// ndst: входной, максимальная длина приемного буфера
// key: входной, закрытый ключ
// alg: hash алгоритм
// Возвращает: длина тела сообщения или код ошибки
int IPRIVAPI Crypt_Sign(const char* src,int nsrc,char* dst,int ndst,IPRIV_KEY* key);
int IPRIVAPI Crypt_SignEx(const char* src,int nsrc,char* dst,int ndst,IPRIV_KEY* key,int alg);

// Формирование отделенной от сообщения подписи.
// src: входной, буфер с телом сообщения
// nsrc: длина сообщения, -1 - считается сама (должен быть нуль-терминатор)
// dst: выходной, буфер для приема тела подписи
// ndst: входной, максимальная длина приемного буфера
// key: входной, закрытый ключ
// alg: hash алгоритм
// Возвращает: длина тела сообщения или код ошибки
int IPRIVAPI Crypt_Sign2(const char* src,int nsrc,char* dst,int ndst,IPRIV_KEY* key);
int IPRIVAPI Crypt_Sign2Ex(const char* src,int nsrc,char* dst,int ndst,IPRIV_KEY* key,int alg);

// Проверка подписи сообщения.
// src: входной, буфер с телом сообщения
// nsrc: длина сообщения, -1 - считается сама (должен быть нуль-терминатор)
// pdst: выходной, может быть 0, адрес указателя, в который помещается адрес оригинального сообщения (до подписи)
// Внимание! pdst указывает на содержимое src, поэтому не удаляйте src до того, как скопируете pdst.
// pndst: выходной, может быть 0, адрес переменной, в которую помещается длина оригинального сообщения (до подписи)
// key: входной, открытый ключ
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_Verify(const char* src,int nsrc,const char** pdst,int* pndst,IPRIV_KEY* key);

// Проверка подписи сообщения произвольного формата.
// src: входной, буфер с телом сообщения
// nsrc: длина сообщения, -1 - считается сама (должен быть нуль-терминатор)
// find_key: входной, адрес функции обратного вызова для поиска открытого ключа отправителя
// pkeyserial: выходной, если не 0, то сюда вернется серийный номер ключа отправителя
// info: выходной, если не 0, то сюда вернется описание ключа
// info_len: входной, длина буфера info
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_Verify2(const char* src,int nsrc,Crypt_FindPublicKey_t find_key,char* info,int info_len,unsigned long* pkeyserial);
int IPRIVAPI Crypt_Verify3(const char* src,int nsrc,const char* sig,int nsig,IPRIV_KEY* key);

// Проверка подписи сообщения произвольной длины.
// src: входной, буфер с телом сообщения
// nsrc: длина сообщения, -1 - считается сама (должен быть нуль-терминатор)
// pdst: выходной, может быть 0, адрес указателя, в который помещается адрес оригинального сообщения (до подписи)
// pndst: выходной, может быть 0, адрес переменной, в которую помещается длина оригинального сообщения (до подписи)
// key: входной, открытый ключ
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_Verify_Detached(const char* src,int nsrc,const char** pdst,int* pndst,IPRIV_KEY* key);

// Шифрование открытым ключом. Длина сообщения не должна превышать длину ключа.
// src: входной, буфер с телом сообщения
// nsrc: длина сообщения, -1 - считается сама (должен быть нуль-терминатор)
// dst: выходной, буфер для приема зашифрованного сообщения
// ndst: входной, максимальная длина приемного буфера
// Возвращает: длина зашифрованного сообщения или код ошибки
int IPRIVAPI Crypt_Encrypt(const char* src,int nsrc,char* dst,int ndst,IPRIV_KEY* key);
int IPRIVAPI Crypt_EncryptLong(const char* src,int nsrc,char* dst,int ndst,IPRIV_KEY* key);

// Дешифрование закрытым ключом.
// src: входной, буфер с зашифрованным сообщением
// nsrc: длина зашифрованного сообщения, -1 - считается сама (должен быть нуль-терминатор)
// dst: выходной, буфер для приема сообщения
// ndst: входной, максимальная длина приемного буфера
// Возвращает: длина сообщения или код ошибки
int IPRIVAPI Crypt_Decrypt(const char* src,int nsrc,char* dst,int ndst,IPRIV_KEY* key);
int IPRIVAPI Crypt_DecryptLong(const char* src,int nsrc,char* dst,int ndst,IPRIV_KEY* key);


// Закрытие ключа.
// key: входной, открытый или закрытый ключ
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_CloseKey(IPRIV_KEY* key);

int IPRIVAPI Crypt_GetKeyBits(IPRIV_KEY* key);


// Деинициализация библиотеки.
// Должна выполняться только один раз при завершении приложения (в основном потоке).
// Возвращает: 0 - успех или код ошибки
int IPRIVAPI Crypt_Done(void);



#ifdef __cplusplus
}
#endif

#endif
