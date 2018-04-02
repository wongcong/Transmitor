using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Client_WPF
{
    public class DataCrypto
    {
        public static AesCryptoServiceProvider GenAesCryptoServiceProvider(string Key)
        {
            AesCryptoServiceProvider AES = new AesCryptoServiceProvider();
            AES.Key = Encoding.ASCII.GetBytes(Key);
            AES.IV = Encoding.ASCII.GetBytes(Key.Substring(0, 16));
            AES.Padding = PaddingMode.Zeros;

            return AES;
        }

        public static byte[] Encrypt(byte[] cipher, AesCryptoServiceProvider AES)
        {
            MemoryStream ms = new MemoryStream();
            ICryptoTransform AESencrypt = AES.CreateEncryptor();
            CryptoStream cryptostream = new CryptoStream(ms, AESencrypt, CryptoStreamMode.Write);
            cryptostream.Write(cipher, 0, cipher.Length);
            cryptostream.FlushFinalBlock();
            byte[] code = ms.ToArray();
            cryptostream.Close();
            ms.Close();

            return code;
        }

        public static byte[] Decrypt(byte[] code, AesCryptoServiceProvider AES)
        {
            MemoryStream ms = new MemoryStream();
            ICryptoTransform AESdecrypt = AES.CreateDecryptor();
            CryptoStream cryptostream = new CryptoStream(ms, AESdecrypt, CryptoStreamMode.Write);
            cryptostream.Write(code, 0, code.Length);
            cryptostream.FlushFinalBlock();
            byte[] cipher = ms.ToArray();
            cryptostream.Close();
            ms.Close();

            return cipher;
        }
    }
}