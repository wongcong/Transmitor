using MahApps.Metro.Controls;
using MaterialDesignThemes.Wpf;
using Microsoft.Win32;
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows;
using System.Windows.Controls;
using static Server_WPF.Command;

namespace Server_WPF
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : MetroWindow
    {
        private int Local_Port = 8088;
        private IPAddress Local_IP;

        private Socket socketWatch = null;
        private Socket socketConn = null;
        private Socket socketRecFile = null;
        private Socket socketSendFile = null;

        private AesCryptoServiceProvider AES;
        private string ExpertResponse;

        private bool IsAuthenticated = false;

        private int Command_Buffer_Size = 1024;
        private int File_Buffer_Size = 1024 * 1024;

        private File_Info SendFileInfo;

        private ReaderWriterLockSlim _rwlock = new ReaderWriterLockSlim();

        private struct File_Info
        {
            public string FileName;
            public long FileLength;

            public File_Info(string name, long length)
            {
                this.FileName = name;
                this.FileLength = length;
            }
        }

        public MainWindow()
        {
            InitializeComponent();
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            IPAddress[] ip = Dns.GetHostByName(Dns.GetHostName()).AddressList;
            foreach (IPAddress i in ip)
            {
                comboBox_localIP.Items.Add(i.ToString());
            }
            comboBox_localIP.SelectedIndex = 0;

            textBox_localPort.Text = Local_Port.ToString();
        }

        private void button_startService_Click(object sender, RoutedEventArgs e)
        {
            button_startService.Content = "正在运行";
            button_startService.IsEnabled = false;
            socketWatch = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint endpoint = new IPEndPoint(Local_IP, Local_Port);
            socketWatch.Bind(endpoint);
            //最多与1个用户建立连接
            socketWatch.Listen(1);

            Thread threadWatch = new Thread(WatchingConn);
            threadWatch.IsBackground = true;
            threadWatch.Start();

            WriteLog("正在监听" + endpoint.ToString());
        }

        private void WatchingConn()
        {
            socketConn = socketWatch.Accept();

            Thread trd = new Thread(Authentication);
            trd.IsBackground = true;
            trd.Start();

            //修改usercontrol的状态显示
            this.Dispatcher.Invoke(new Action(() =>
            {
                listBox_onlineUser.Items.Add(socketConn.RemoteEndPoint.ToString());
                WriteLog(socketConn.RemoteEndPoint.ToString() + "已连接");
                snackbar.MessageQueue.Enqueue("用户接入");
            }));
        }

        private void Authentication()
        {
            while (true)
            {
                int length = -1;
                byte[] buffer = new byte[Command_Buffer_Size];
                try
                {
                    length = socketConn.Receive(buffer);
                }
                catch (Exception ex)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog(ex.ToString());
                        WriteLog("连接已断开");

                        ResetAuthenInfo();

                        //重新开始监听
                        Thread threadWatch = new Thread(WatchingConn);
                        threadWatch.IsBackground = true;
                        threadWatch.Start();

                    }));
                    break;
                }

                if (length <= 0)
                {
                    continue;
                }

                byte[] message = new byte[length];
                Array.Copy(buffer, message, length);

                Authen_Message am = (Authen_Message)Byte2Message(message, "Authen_Message");

                this.Dispatcher.Invoke(new Action(() =>
                {
                    listBox_packetInfo.Items.Insert(0, am.MessageInfo());
                }));

                if (IsTimeOut(DateTime.Now))
                {
                    Authen_Message au = new Authen_Message(Status_Flag.Time_Out, DateTime.Now, null);
                    socketConn.Send(Message2Byte(au));
                    WriteLog("接收到超时的命令");
                }

                if (am.Flag == Status_Flag.Response_Challenge)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        textBox_recRespomse.Text = am.Extend;
                        WriteLog("收到回应" + am.Extend);
                        snackbar.MessageQueue.Enqueue("收到回应");
                    }));

                    if (ExpertResponse == am.Extend)
                    {
                        Authen_Message au = new Authen_Message(Status_Flag.Authen_Success, DateTime.Now, null);
                        socketConn.Send(Message2Byte(au));

                        IsAuthenticated = true;

                        this.Dispatcher.Invoke(new Action(() =>
                        {
                            WriteLog("用户认证成功，密钥协商完毕，发送就绪");
                            snackbar.MessageQueue.Enqueue("用户认证成功");
                        }));

                        Thread trd = new Thread(TransControl);
                        trd.IsBackground = true;
                        trd.Start();

                        break;
                    }
                    else
                    {
                        Authen_Message au = new Authen_Message(Status_Flag.Authen_Failed, DateTime.Now, null);
                        socketConn.Send(Message2Byte(au));

                        this.Dispatcher.Invoke(new Action(() =>
                        {
                            WriteLog("认证失败，您可以选择重新认证");
                            snackbar.MessageQueue.Enqueue("用户认证失败");
                        }));
                    }

                }


            }
        }

        private void ResetAuthenInfo()
        {
            this.Dispatcher.Invoke(new Action(() =>
            {
                listBox_onlineUser.Items.Clear();
                textBox_challengeValue.Clear();
                textBox_expertResponse.Clear();
                textBox_recRespomse.Clear();
                textBox_key.Clear();
            }));

            //要求重新认证
            IsAuthenticated = false;
        }

        private void TransControl()
        {
            while (true)
            {
                int length = -1;
                byte[] buffer = new byte[Command_Buffer_Size];
                try
                {
                    length = socketConn.Receive(buffer);
                }
                catch (Exception ex)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog(ex.ToString());
                        WriteLog("连接已断开");

                        snackbar.MessageQueue.Enqueue("连接已断开, 即将重新启动监听");
                        ResetAuthenInfo();

                        //重新开始监听
                        Thread threadWatch = new Thread(WatchingConn);
                        threadWatch.IsBackground = true;
                        threadWatch.Start();

                        WriteLog("开始监听");

                    }));
                    break;
                }

                if (length <= 0)
                {
                    continue;
                }

                byte[] message = new byte[length];
                Array.Copy(buffer, message, length);

                TransCtrl_Message tm = (TransCtrl_Message)Byte2Message(message, "TransCtrl_Message");

                this.Dispatcher.Invoke(new Action(() =>
                {
                    listBox_packetInfo.Items.Insert(0, tm.MessageInfo());
                }));

                if (tm.Flag == Status_Flag.Transmit_Request)
                {
                    string file_length;
                    if (tm.FileLength > 1024 * 1024 * 1024)
                    {
                        double fl = (double)tm.FileLength / (1024 * 1024 * 1024);
                        file_length = fl.ToString("f2") + "GB";
                    }
                    else if (tm.FileLength > 1024 * 1024)
                    {
                        double fl = (double)tm.FileLength / (1024 * 1024);
                        file_length = fl.ToString("f2") + "MB";
                    }
                    else if (tm.FileLength > 1024)
                    {
                        double fl = (double)tm.FileLength / 1024;
                        file_length = fl.ToString("f2") + "KB";
                    }
                    else
                    {
                        file_length = tm.FileLength.ToString() + "B";
                    }

                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog("收到文件传输请求");

                        dialogHost_TextBox_FileName.Text = tm.FileName;
                        dialogHost_TextBox_FileLength.Text = tm.FileLength.ToString();
                        this.Height += 40;
                        snackbar_RecMessage.IsActive = true;
                    }));
                }

                if (tm.Flag == Status_Flag.Transmit_Allow)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog("对方准备接收");

                        ParameterizedThreadStart pts = new ParameterizedThreadStart(SendFile);
                        Thread threadWatch = new Thread(pts);
                        threadWatch.IsBackground = true;
                        threadWatch.Start(SendFileInfo);
                    }));
                }

                if (tm.Flag == Status_Flag.Transmit_Cancel)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog("对方拒绝接收");

                        snackbar.MessageQueue.Enqueue("对方拒绝接收");
                    }));
                }

                if (tm.Flag == Status_Flag.Transmit_Over)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog("对方请求校验文件");
                        WriteLog("校验值为" + tm.FileName);
                        snackbar.MessageQueue.Enqueue("正在校验");
                    }));

                    //计算校验值
                    string file_hash = null;
                    using (MD5 md5Hash = MD5.Create())
                    {
                        FileStream fs = new FileStream(SendFileInfo.FileName, FileMode.Open, FileAccess.Read);
                        byte[] hash = md5Hash.ComputeHash(fs);
                        file_hash = Convert.ToBase64String(hash);
                    }

                    if (file_hash == tm.FileName)
                    {
                        //回送消息
                        TransCtrl_Message tcm = new TransCtrl_Message(Status_Flag.VerifySuccess, DateTime.Now, null, 0);
                        socketConn.Send(Message2Byte(tcm));

                        this.Dispatcher.Invoke(new Action(() =>
                        {
                            WriteLog("本地校验值为" + file_hash);
                            WriteLog("校验成功");
                            snackbar.MessageQueue.Enqueue("校验成功，文件发送成功");
                        }));
                    }
                    else
                    {
                        //回送消息
                        TransCtrl_Message tcm = new TransCtrl_Message(Status_Flag.VerifyFailed, DateTime.Now, null, 0);
                        socketConn.Send(Message2Byte(tcm));

                        this.Dispatcher.Invoke(new Action(() =>
                        {
                            WriteLog("本地校验值为" + file_hash);
                            WriteLog("校验失败");
                            snackbar.MessageQueue.Enqueue("校验失败，文件发送失败");
                        }));
                    }
                }

                if (tm.Flag == Status_Flag.VerifySuccess)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog("校验成功，文件可用");
                        snackbar.MessageQueue.Enqueue("校验成功，文件可用");
                    }));
                }

                if (tm.Flag == Status_Flag.VerifyFailed)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog("校验失败，文件不可用");
                        snackbar.MessageQueue.Enqueue("校验失败，文件不可用");
                    }));
                }
            }
        }

        private void snackbar_RecMessage_ActionClick(object sender, RoutedEventArgs e)
        {
            this.Dispatcher.Invoke(new Action(() =>
            {
                snackbar_RecMessage.IsActive = false;
                this.Height -= 40;
                dialogHost.IsOpen = true;
            }));
        }

        private void dialogHost_DialogClosing(object sender, DialogClosingEventArgs eventArgs)
        {
            if (Equals(eventArgs.Parameter, true))
            {
                //确认接收
                SaveFileDialog sfd = new SaveFileDialog();
                sfd.Filter = "All files(*.*)|*.*";
                sfd.FileName = dialogHost_TextBox_FileName.Text;
                sfd.InitialDirectory = Environment.CurrentDirectory;
                if (sfd.ShowDialog() == true)
                {
                    ParameterizedThreadStart pts = new ParameterizedThreadStart(RecFile);
                    Thread trd = new Thread(pts);
                    trd.IsBackground = true;

                    File_Info fi = new File_Info(sfd.FileName, Convert.ToInt64(dialogHost_TextBox_FileLength.Text));

                    trd.Start(fi);

                    TransCtrl_Message tm = new TransCtrl_Message(Status_Flag.Transmit_Allow, DateTime.Now, dialogHost_TextBox_FileName.Text, 0);
                    socketConn.Send(Message2Byte(tm));
                }
            }
            else
            {
                //拒绝接收
                TransCtrl_Message tm = new TransCtrl_Message(Status_Flag.Transmit_Cancel, DateTime.Now, dialogHost_TextBox_FileName.Text, 0);
                socketConn.Send(Message2Byte(tm));
            }
        }

        private void comboBox_localIP_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            Local_IP = IPAddress.Parse(comboBox_localIP.SelectedItem.ToString());
        }

        private void button_genRandom_Click(object sender, RoutedEventArgs e)
        {
            //连接可用性判断
            if (socketConn == null || !socketConn.Connected)
            {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    snackbar.MessageQueue.Enqueue("无可用连接");
                }));
                return;
            }
            //如果已经认证通过就不需要再验证了
            if (IsAuthenticated)
            {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    snackbar.MessageQueue.Enqueue("已认证通过，无需再次操作");
                }));
                return;
            }
            //生成一个100000-999999随机数作为挑战值challenge_value
            //要求对方收到挑战值后，对称密钥加密回送应答
            int challenge_value = new Random().Next(100000, 999999);
            textBox_challengeValue.Text = challenge_value.ToString();

            StringBuilder sBuilder = new StringBuilder();

            byte[] hash;
            string Key;
            using (MD5 md5Hash = MD5.Create())
            {
                //生成密钥
                //Hash((1-challenge_value).ToString())作为预定密钥
                hash = md5Hash.ComputeHash(Encoding.UTF8.GetBytes((1 - challenge_value).ToString()));
                foreach (byte b in hash)
                {
                    sBuilder.Append(b.ToString("x2"));
                }
                Key = sBuilder.ToString();
                textBox_key.Text = sBuilder.ToString();

                //计算响应值
                //Hash(Hash(challenge_value.ToString()))为应答
                hash = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(challenge_value.ToString()));
                hash = md5Hash.ComputeHash(hash);
            }

            //计算响应密文(期望响应)
            AES = DataCrypto.GenAesCryptoServiceProvider(Key);
            //字符串采用base64编码
            ExpertResponse = Convert.ToBase64String(DataCrypto.Encrypt(hash, AES));
            textBox_expertResponse.Text = ExpertResponse;

            Authen_Message am = new Authen_Message(Status_Flag.Start_Challenge, DateTime.Now, challenge_value.ToString());
            socketConn.Send(Message2Byte(am));

            WriteLog("发起挑战，值为" + challenge_value.ToString());
            WriteLog("生成预共享密钥");
            snackbar.MessageQueue.Enqueue("发起挑战");
        }

        private void button_chooseFile_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.InitialDirectory = Environment.CurrentDirectory;
            ofd.Filter = "所有文件|*.*";
            if (ofd.ShowDialog() == true)
            {
                textBox_filePath.Text = ofd.FileName;
            }
        }

        private void button_sendFile_Click(object sender, RoutedEventArgs e)
        {
            if (!IsAuthenticated)
            {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    snackbar.MessageQueue.Enqueue("请先进行认证");
                }));
                return;
            }

            FileInfo fi = null;
            try
            {
                fi = new FileInfo(textBox_filePath.Text);

                if (!fi.Exists)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        snackbar.MessageQueue.Enqueue("文件不存在，请重新选择文件");
                    }));
                    return;
                }
            }
            catch
            {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    snackbar.MessageQueue.Enqueue("文件路径有误");
                }));
                return;
            }

            TransCtrl_Message tm = new TransCtrl_Message(Status_Flag.Transmit_Request, DateTime.Now, fi.Name, fi.Length);
            socketConn.Send(Message2Byte(tm));

            SendFileInfo = new File_Info(textBox_filePath.Text, fi.Length);
        }

        private void RecFile(object fileParam)
        {
            File_Info fi = (File_Info)fileParam;

            //开始监听文件传送端口
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint iep = new IPEndPoint(((IPEndPoint)socketConn.LocalEndPoint).Address, 8089);
            socket.Bind(iep);
            socket.Listen(1);

            try
            {
                socketRecFile = socket.Accept();
                socket.Close();
            }
            catch
            {
                WriteLog("传输端口无响应");
                snackbar.MessageQueue.Enqueue("传输端口无响应");
            }
            this.Dispatcher.Invoke(new Action(() =>
            {
                WriteLog("开始接收 " + new FileInfo(fi.FileName).Name);
                snackbar.MessageQueue.Enqueue("开始接收 " + new FileInfo(fi.FileName).Name);
            }));

            //开一个线程进行解密
            ParameterizedThreadStart pts = new ParameterizedThreadStart(DecryptData);
            Thread trd = new Thread(pts);
            trd.IsBackground = true;
            trd.Start(fi);

            this.Dispatcher.Invoke(new Action(() =>
            {
                progressBar_recFile.Minimum = 0;
                progressBar_recFile.Maximum = fi.FileLength;
            }));

            //填充后的长度
            long file_length = fi.FileLength + ((fi.FileLength % 16 == 0) ? 0 : (16 - fi.FileLength % 16));
            long offset = 0;
            while (true)
            {
                int length = -1;
                byte[] buffer = new byte[File_Buffer_Size];
                try
                {
                    length = socketRecFile.Receive(buffer);
                }
                catch (Exception ex)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog(ex.ToString());
                        WriteLog("传输连接已断开");

                        snackbar.MessageQueue.Enqueue("传输连接已断开，停止接收 " + new FileInfo(fi.FileName).Name);
                    }));
                    break;
                }
                _rwlock.EnterWriteLock();
                FileWrite(fi.FileName + ".tmp", offset, length, buffer);
                _rwlock.ExitWriteLock();
                offset += length;

                this.Dispatcher.Invoke(new Action(() =>
                {
                    progressBar_recFile.Value = offset;
                }));


                if (offset >= file_length)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog(new FileInfo(fi.FileName).Name + "接收完毕");
                        snackbar.MessageQueue.Enqueue(new FileInfo(fi.FileName).Name + "接收完毕");

                        progressBar_recFile.IsIndeterminate = true;
                        try
                        {
                            socketRecFile.Close();
                        }
                        catch (Exception ex)
                        {
                            WriteLog(ex.ToString());
                        }
                        socketRecFile = null;
                    }));
                    break;
                }

                System.GC.Collect();
            }

            System.GC.Collect();
        }

        private void DecryptData(object fileParam)
        {
            File_Info fi = (File_Info)fileParam;

            //填充后的长度
            long file_length = fi.FileLength + ((fi.FileLength % 16 == 0) ? 0 : (16 - fi.FileLength % 16));
            long read_offset = 0;
            long write_offset = 0;
            //需要读取的长度
            int read_size = File_Buffer_Size;
            int write_size = File_Buffer_Size;

            while (true)
            {
                //如果是最后一个分块则修改size
                if (read_offset + File_Buffer_Size > file_length)
                {
                    read_size = (int)(file_length % (long)File_Buffer_Size);
                    write_size = (int)(fi.FileLength % (long)File_Buffer_Size);
                }

                while (true)
                {
                    //如果不足一块则等待
                    if (!File.Exists(fi.FileName + ".tmp") || new FileInfo(fi.FileName + ".tmp").Length < read_offset + read_size)
                    {
                        continue;
                    }
                    break;
                }

                _rwlock.EnterReadLock();
                byte[] Read_Buffer = FileRead(fi.FileName + ".tmp", read_offset, read_size);
                _rwlock.ExitReadLock();
                read_offset += read_size;

                byte[] Write_Buffer = null;
                try
                {
                    Write_Buffer = DataCrypto.Decrypt(Read_Buffer, AES);
                }
                catch (Exception ex)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog(ex.ToString());
                        WriteLog("数据块解密过程出错");
                        snackbar.MessageQueue.Enqueue("数据块解密过程出错");

                        //终止传输
                        try
                        {
                            socketRecFile.Shutdown(SocketShutdown.Both);
                            socketRecFile.Close();
                            socketRecFile = null;
                        }
                        catch (Exception e)
                        {
                            WriteLog(e.ToString());
                            WriteLog("停止接收 " + new FileInfo(fi.FileName).Name);
                            snackbar.MessageQueue.Enqueue("停止接收" + new FileInfo(fi.FileName).Name);
                        }
                    }));
                    break;
                }

                FileWrite(fi.FileName, write_offset, write_size, Write_Buffer);

                write_offset += write_size;

                if (write_offset >= fi.FileLength)
                {
                    //删除tmp文件
                    File.Delete(fi.FileName + ".tmp");

                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog(new FileInfo(fi.FileName).Name + " 解密完毕，正在计算校验值");
                        snackbar.MessageQueue.Enqueue(new FileInfo(fi.FileName).Name + "解密完毕");

                        progressBar_recFile.IsIndeterminate = false;
                    }));

                    //计算校验值
                    string file_hash = null;
                    using (MD5 md5Hash = MD5.Create())
                    {
                        FileStream fs = new FileStream(fi.FileName, FileMode.Open, FileAccess.Read);
                        byte[] hash = md5Hash.ComputeHash(fs);
                        file_hash = Convert.ToBase64String(hash);
                    }

                    //回送消息
                    TransCtrl_Message tm = new TransCtrl_Message(Status_Flag.Transmit_Over, DateTime.Now, file_hash, 0);
                    socketConn.Send(Message2Byte(tm));

                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog(new FileInfo(fi.FileName).Name + " 的本地校验值为" + file_hash);
                        WriteLog("发送 " + new FileInfo(fi.FileName).Name + " 的校验值");
                        snackbar.MessageQueue.Enqueue("等待对方校验");
                    }));
                    break;
                }
            }
        }

        private void SendFile(object fileParam)
        {
            File_Info fi = (File_Info)fileParam;

            socketSendFile = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint iep = new IPEndPoint(((IPEndPoint)socketConn.RemoteEndPoint).Address, 8089);

            try
            {
                socketSendFile.Connect(iep);
            }
            catch
            {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    WriteLog("传输端口无响应");
                    snackbar.MessageQueue.Enqueue("传输端口无响应");
                }));
            }
            this.Dispatcher.Invoke(new Action(() =>
            {
                WriteLog("开始发送 " + new FileInfo(fi.FileName).Name);
                snackbar.MessageQueue.Enqueue("开始发送 " + new FileInfo(fi.FileName).Name);
            }));

            long offset = 0;
            this.Dispatcher.Invoke(new Action(() =>
            {
                progressBar_sendFile.Minimum = 0;
                progressBar_sendFile.Maximum = fi.FileLength;

                button_sendFile.IsEnabled = false;
            }));

            while (true)
            {
                //读取文件块
                byte[] Read_buffer = FileRead(fi.FileName, offset, File_Buffer_Size);
                int length = Read_buffer.Length;
                offset += length;

                //加密文件块
                byte[] Send_Buffer = DataCrypto.Encrypt(Read_buffer, AES);
                try
                {
                    length = socketSendFile.Send(Send_Buffer);
                }
                catch (Exception ex)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog(ex.ToString());
                        WriteLog("传输连接已断开");

                        snackbar.MessageQueue.Enqueue("传输连接已断开，停止发送 " + new FileInfo(fi.FileName).Name);
                    }));
                    break;
                }

                this.Dispatcher.Invoke(new Action(() =>
                {
                    progressBar_sendFile.Value = offset;
                }));

                if (offset >= fi.FileLength)
                {
                    this.Dispatcher.Invoke(new Action(() =>
                    {
                        WriteLog(new FileInfo(fi.FileName).Name + "发送完毕");
                        snackbar.MessageQueue.Enqueue(new FileInfo(fi.FileName).Name + "发送完毕");
                        socketSendFile.Shutdown(SocketShutdown.Both);
                        socketSendFile.Close();
                        socketSendFile = null;
                    }));
                    break;
                }
                System.GC.Collect();
            }

            this.Dispatcher.Invoke(new Action(() =>
            {
                button_sendFile.IsEnabled = true;
            }));
            System.GC.Collect();
        }

        private static void FileWrite(string path, long begin_point, int length, byte[] data)
        {
            using (System.IO.FileStream stream = System.IO.File.OpenWrite(path))
            {
                stream.Seek(begin_point, System.IO.SeekOrigin.Begin);
                stream.Write(data, 0, length);
                stream.Flush();
                stream.Close();
            }
        }

        //从指定文件的指定位置读取指定数量的字节，如不够，返回读到的字节数
        private static byte[] FileRead(string path, long begin_point, int size)
        {
            byte[] result = null;
            long length = begin_point + size;

            using (FileStream stream = File.OpenRead(path))
            {
                if (begin_point >= stream.Length)
                    return null;

                if (length > stream.Length)
                    result = new byte[stream.Length - begin_point];
                else
                    result = new byte[size];
                stream.Seek(begin_point, SeekOrigin.Begin);
                stream.Read(result, 0, result.Length);
                stream.Close();
            }

            return result;
        }

        private bool IsTimeOut(DateTime t)
        {
            TimeSpan ts = DateTime.Now - t;
            //时间差设置为1秒
            if (ts.TotalSeconds < 1)
                return false;
            else
                return true;
        }

        private void WriteLog(string log)
        {
            this.Dispatcher.Invoke(new Action(() =>
            {
                listBox_Log.Items.Insert(0, "[" + DateTime.Now.ToShortTimeString() + "]" + log);
            }));
        }

        private void File_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                textBox_filePath.Text = ((System.Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();
            }
        }

        private void textBox_filePath_PreviewDragOver(object sender, DragEventArgs e)
        {
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
        }

        private void textBox_filePath_PreviewDrop(object sender, DragEventArgs e)
        {
            textBox_filePath.Text = ((System.Array)e.Data.GetData(DataFormats.FileDrop)).GetValue(0).ToString();
        }
    }
}
