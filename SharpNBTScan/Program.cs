using System;
using System.Net;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Collections;
using System.Globalization;

namespace SharpNBTScan
{
    class Program
    {
        private static byte[] nbtstat = new byte[] {
            0xee, 0x33, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
            0x00, 0x01 
            };

        /// <summary>
        /// 16 进制转 byte[] 数组
        /// </summary>
        private static byte[] Hex2Byte(String hexContent)
        {
            // 需要将 hex 转换成 byte 数组。 
            byte[] bytes = new byte[hexContent.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                // 每两个字符是一个 byte。 
                bytes[i] = byte.Parse(hexContent.Substring(i * 2, 2), NumberStyles.HexNumber);
            }
            return bytes;
        }

        private static string Conversion(String SourceString, int left, int right)
        {
            return Encoding.Default.GetString(Hex2Byte(SourceString.Substring(left, right)));
        }

        /// <summary>
        /// 以固定长度拆分字符串
        /// </summary>
        private static ArrayList SplitLength(string SourceString, int Length)
        {
            ArrayList list = new ArrayList();
            for (int i = 0; i < SourceString.Trim().Length; i += Length)
            {
                if ((SourceString.Trim().Length - i) >= Length)
                    list.Add(SourceString.Trim().Substring(i, Length));
                else
                    list.Add(SourceString.Trim().Substring(i, SourceString.Trim().Length - i));
            }
            return list;
        }

        /// <summary>
        /// 主功能函数
        /// </summary>
        private static void DetectionNBTscan(String host)
        {
            String response = String.Empty;

            IPAddress ipAddress = IPAddress.Parse(host);
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 137);

            response = String.Format("\n[*] Detecting Remote Computer of {0}\n", host);
            try
            {
                byte[] response_v0 = new byte[1024];
                using (var sock = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    sock.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReceiveTimeout, 3000);
                    sock.Connect(remoteEP);

                    sock.Send(nbtstat);
                    sock.Receive(response_v0);
                }

                string NumberName = Convert.ToString(response_v0[56], 10);

                response += String.Format("  [+] Data length: {0}\n  [+] Number of Names: {1}", Convert.ToString(response_v0[55], 10), NumberName);


                // 开始处理数据内容(这种解析方式属于取巧，不耐用)：每个 Name 都是 18 个字节数组，如果转为 String 则为 36 个字符
                string[] response_v1 = BitConverter.ToString(response_v0.Skip(57).ToArray()).Replace("-", "").Split(new String[] { "00000000" }, StringSplitOptions.RemoveEmptyEntries);
                ArrayList strList = SplitLength(response_v1[0], 36);
                foreach (string str in strList)
                {
                    String Flags = str.Substring(str.Length - 6, 2);
                    String NameFlags = str.Substring(str.Length - 4);

                    if (Flags == "00" && NameFlags == "0400")
                    {
                        response += String.Format("\n    [>] Name type: Unique name -> (Workstation/Redirector) -> Name: {0}<{1}>", Conversion(str, 0, 30), Flags);
                    }
                    else if (Flags == "00" && NameFlags == "8400")
                    {
                        response += String.Format("\n    [>] Name type: Group name -> (Workstation/Redirector) -> Name: {0}<{1}>", Conversion(str, 0, 30), Flags);
                    }
                    else if (Flags == "1C" && NameFlags == "8400")
                    {
                        response += String.Format("\n    [>] Name type: Group name -> (Domain Controllers) -> Name: {0}<{1}>", Conversion(str, 0, 30), Flags);
                    }
                    else if (Flags == "20" && NameFlags == "0400")
                    {
                        response += String.Format("\n    [>] Name type: Unique name -> (Server service) -> Name: {0}<{1}>", Conversion(str, 0, 30), Flags);
                    }
                    else if (Flags == "1B" && NameFlags == "0400")
                    {
                        response += String.Format("\n    [>] Name type: Unique name -> (Domain Master Browser) -> Name: {0}<{1}>", Conversion(str, 0, 30), Flags);
                    }
                    else if (Flags == "1E" && NameFlags == "8400")
                    {
                        response += String.Format("\n    [>] Name type: Group name -> (Browser Election Service) -> Name: {0}<{1}>", Conversion(str, 0, 30), Flags);
                    }
                    else if (Flags == "1D" && NameFlags == "0400")
                    {
                        response += String.Format("\n    [>] Name type: Unique name -> (Local Master Browser) -> Name: {0}<{1}>", Conversion(str, 0, 30), Flags);
                    }
                    else if (str.Substring(0, 4) == "0102" && NameFlags == "8400")
                    {
                        response += String.Format("\n    [>] Name type: Unique name -> (Browser) -> Name: {0}<{1}>", Conversion(str, 4, 25), Flags);
                    }
                    else if (str.Length == 12)
                    {
                        String uintid = String.Empty;
                        for (int i = 0; i < str.Length / 2; i++)
                        {
                            uintid += str.Substring(i * 2, 2) + "-";
                        }
                        response += String.Format("\n    [>] Uint ID(MAC Address): {0}", uintid.Substring(0, uintid.LastIndexOf('-')));
                    }
                }

                Console.WriteLine(response);
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] Error: {0}", ex.Message);
            }
        }

        static void Main(string[] args)
        {

            string host = args[0];
            /*
             * 多线程（线程池）处理
             */
            DetectionNBTscan(host);
        }
    }
}
