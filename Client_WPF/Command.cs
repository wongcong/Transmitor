using System;
using System.Runtime.InteropServices;

namespace Client_WPF
{
    public enum Status_Flag
    {
        Start_Challenge = 1,
        Response_Challenge,
        Authen_Success,
        Authen_Failed,
        Time_Out,

        Transmit_Request,
        Transmit_Allow,
        Transmit_Cancel,
        Transmit_Over,

        VerifySuccess,
        VerifyFailed
    }


    public struct Authen_Message
    {
        public Status_Flag Flag;
        public DateTime Time;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Extend;

        public Authen_Message(Status_Flag flag, DateTime t, string str)
        {
            this.Flag = flag;
            this.Time = t;
            this.Extend = str;
        }

        public string MessageInfo()
        {
            return "{\n   FLAG : " + Flag.ToString() + "\n   TIME : " + Time.ToLongTimeString() + "\n   Exten : " + Extend + "\n}";
        }
    }

    public struct TransCtrl_Message
    {
        public Status_Flag Flag;
        public DateTime Time;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string FileName;
        public long FileLength;

        public TransCtrl_Message(Status_Flag flag, DateTime t, string file_naem, long file_length)
        {
            this.Flag = flag;
            this.Time = t;
            this.FileName = file_naem;
            this.FileLength = file_length;
        }

        public string MessageInfo()
        {
            return "{\n   FLAG : " + Flag.ToString() + "\n   TIME : " + Time.ToLongTimeString() + "\n   FileName : " + FileName + "\n   FileLength : " + FileLength.ToString() + "\n}";
        }
    }

    class Command
    {
        //将byte[]数据转换为TCP包
        public static object Byte2Message(byte[] data, string messageType)
        {
            return ByteConvertHelper.Bytes2Object(data, Type.GetType("Client_WPF." + messageType));
        }

        //将TcP包的内容转换为byte
        public static byte[] Message2Byte(Authen_Message am)
        {
            return ByteConvertHelper.Object2Bytes(am);
        }

        public static byte[] Message2Byte(TransCtrl_Message am)
        {
            return ByteConvertHelper.Object2Bytes(am);
        }
    }
}