using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Security.Cryptography;

namespace MiRouter
{

    public struct MiRouterBaseKey
    {
        public string key { set; get; }
        public string iv { set; get; }
        public string devicemac { set; get; }
        public string Name { set; get; }
        public string Device_ID { set; get; }
        public string HardWareVersion { set; get; }
        public string RomVersion { set; get; }
        public string RomChannel { set; get; }
        public string ccode { set; get; }
        public string ConnectUrl { get; set; }
        public string token { get; set; }
    }

    public class MiRouterHelper
    {
        MiRouterBaseKey amirouterinfo = new MiRouterBaseKey();
        /// <summary>
        /// Init and Get key
        /// </summary>
        /// <param name="url">Default:http://192.168.31.1</param>
        public MiRouterHelper(string url = "http://192.168.31.1")
        {
            amirouterinfo.ConnectUrl = url;
            string result;
            HttpWebRequest httpRequest = (HttpWebRequest)WebRequest.Create(amirouterinfo.ConnectUrl + "/cgi-bin/luci/web");
            httpRequest.Method = "GET";
            HttpWebResponse wbResponse = (HttpWebResponse)httpRequest.GetResponse();
            using (Stream responseStream = wbResponse.GetResponseStream())
            {
                using (StreamReader sReader = new StreamReader(responseStream))
                {
                    result = sReader.ReadToEnd();
                }
            }
            string key = result.IndexOf("key: '") != -1 ? result.Substring(result.IndexOf("key: '") + 6, result.IndexOf("',", result.IndexOf("key: '") + 6) - result.IndexOf("key: '") - 6) : null;
            string iv = result.IndexOf("iv: '") != -1 ? result.Substring(result.IndexOf("iv: '") + 5, result.IndexOf("',", result.IndexOf("iv: '") + 5) - result.IndexOf("iv: '") - 5) : null;
            string devicemac = result.IndexOf("var deviceId = '") != -1 ? result.Substring(result.IndexOf("var deviceId = '") + 16, result.IndexOf("';", result.IndexOf("var deviceId = '") + 16) - result.IndexOf("var deviceId = '") - 16) : null;

            if (key == null || iv == null || devicemac == null)
            {
                throw new Exception("Initialization failed - Because can not found the key or iv or deviceid.");
            }

            amirouterinfo.key = key;
            amirouterinfo.iv = iv;
            amirouterinfo.devicemac = devicemac;
            Console.WriteLine("[+]Key: " + key);
            Console.WriteLine("[+]iv: " + iv);
            Console.WriteLine("[+]deviceid: " + devicemac);

            //Update status
            amirouterinfo.Name = result.IndexOf("<div class=\"rtname\">")!=-1?result.Substring(result.IndexOf("<div class=\"rtname\">") + 20, result.IndexOf("</div> -->", result.IndexOf("<div class=\"rtname\">") + 20) - result.IndexOf("<div class=\"rtname\">") - 20).Trim():null;
            amirouterinfo.Device_ID = result.IndexOf("deviceId: '")!=-1?result.Substring(result.IndexOf("deviceId: '") + 11, result.IndexOf("'", result.IndexOf("deviceId: '") + 11) - result.IndexOf("deviceId: '") - 11):null;
            amirouterinfo.RomVersion = result.IndexOf("romVersion: '") != -1 ? result.Substring(result.IndexOf("romVersion: '") + 13, result.IndexOf("'", result.IndexOf("romVersion: '") + 13) - result.IndexOf("romVersion: '") - 13) : null;
            amirouterinfo.RomChannel = result.IndexOf("romChannel: '")!=-1?result.Substring(result.IndexOf("romChannel: '") + 13, result.IndexOf("'", result.IndexOf("romChannel: '") + 13) - result.IndexOf("romChannel: '") - 13):null;
            amirouterinfo.HardWareVersion = result.IndexOf("hardwareVersion: '")!=-1? result.Substring(result.IndexOf("hardwareVersion: '") + 18, result.IndexOf("'", result.IndexOf("hardwareVersion: '") + 18) - result.IndexOf("hardwareVersion: '") - 18):null;
            amirouterinfo.ccode = result.IndexOf("ccode = '")!=-1?result.Substring(result.IndexOf("ccode = '") + 9, result.IndexOf("'", result.IndexOf("ccode = '") + 9) - result.IndexOf("ccode = '") - 9):null;
            Console.WriteLine($"[+]Router Detial: {amirouterinfo.Name}_{amirouterinfo.Device_ID}_{amirouterinfo.RomVersion}_{amirouterinfo.RomChannel}_{amirouterinfo.HardWareVersion}_{amirouterinfo.ccode}");


        }
        /// <summary>
        /// Connect The mi Router and Get stok
        /// </summary>
        /// <param name="password">Login Password</param>        
        /// <param name="username">Login Username default: admin</param>
        /// <param name="ConnectUrl">Login Url</param>
        public MiRouterBaseKey LoginToGetBaseKey(string password, string username = "admin")
        {
            string token;
            Random rand = new Random();
            int random = rand.Next(100, 9999);
            DateTime DateNow = DateTime.Now;
            long UnixDate = (DateTime.Now.ToUniversalTime().Ticks - 621355968000000000) / 10000000;
            string EncryptInit = $"0_{amirouterinfo.devicemac}_{UnixDate}_{random}";
            Console.WriteLine("[+]Encrypt.Init: " + EncryptInit);
            string secret_passwd = SHA1(EncryptInit + SHA1(password + amirouterinfo.key, Encoding.UTF8).ToLower(), Encoding.UTF8).ToLower();
            Console.WriteLine("[+]secret: " + secret_passwd);
            var request = (HttpWebRequest)WebRequest.Create(amirouterinfo.ConnectUrl + "/cgi-bin/luci/api/xqsystem/login");
            var postData = $"username={username}&password={secret_passwd}&logtype=2&nonce={EncryptInit}";
            var data = Encoding.ASCII.GetBytes(postData);
            request.Method = "POST";
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = data.Length;
            using (var stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
            }
            var response = (HttpWebResponse)request.GetResponse();
            var responseString = new StreamReader(response.GetResponseStream()).ReadToEnd();
            //Console.WriteLine(responseString);
            if (responseString.IndexOf("not auth") != -1)
            {
                throw new Exception("Login Password Error!!");
            }
            token = responseString.Substring(responseString.IndexOf("stok=") + 5, responseString.IndexOf("/web/home") - responseString.IndexOf("stok=") - 5);
            Console.WriteLine("[!]Login Successful!");
            Console.WriteLine("[+]Token: " + token);
            amirouterinfo.token = token;
            return amirouterinfo;

        }
        /// <summary>
        /// Check if the token is valid
        /// It will sent a GET wbRequest to Check token
        /// </summary>
        /// <returns>token_key</returns>
        public void LoginOut()
        {
            HttpWebRequest httpRequest = (HttpWebRequest)WebRequest.Create(amirouterinfo.ConnectUrl + $"/cgi-bin/luci/;stok={amirouterinfo.token}/web/logout");
            httpRequest.Method = "GET";
            HttpWebResponse wbResponse = (HttpWebResponse)httpRequest.GetResponse();
        }

        public bool CheckToken(string token)
        {
            // http://192.168.31.1/cgi-bin/luci/;stok=STOK/api/misystem/status

            string result;
            HttpWebRequest wbRequest = (HttpWebRequest)WebRequest.Create(amirouterinfo.ConnectUrl + "//cgi-bin/luci/;stok=" + token + "/api/misystem/status");
            wbRequest.Method = "GET";
            HttpWebResponse wbResponse = (HttpWebResponse)wbRequest.GetResponse();
            using (Stream responseStream = wbResponse.GetResponseStream())
            {
                using (StreamReader sReader = new StreamReader(responseStream))
                {
                    result = sReader.ReadToEnd();
                }
            }
            return result.IndexOf("Invalid token") != -1 ? false : true;
        }
        private string SHA1(string content, Encoding encode)
        {
            try
            {
                SHA1 sha1 = new SHA1CryptoServiceProvider();
                byte[] bytes_in = encode.GetBytes(content);
                byte[] bytes_out = sha1.ComputeHash(bytes_in);
                sha1.Dispose();
                string result = BitConverter.ToString(bytes_out);
                result = result.Replace("-", "");
                return result;
            }
            catch (Exception ex)
            {
                throw new Exception("SHA1 Error" + ex.Message);
            }
        }
        
    }

    public class MiRouterAPI
    {
        MiRouterBaseKey amirouterinfo = new MiRouterBaseKey();
        public MiRouterAPI(MiRouterBaseKey token)
        {
            amirouterinfo = token;
        }
        /// <summary>
        /// It will return JSON File
        /// </summary>
        /// <returns></returns>
        public MiRouterBaseKey GetMiRouterBaseKey()
        {
            return amirouterinfo;
        }
        public bool CheckToken()
        {
            // http://192.168.31.1/cgi-bin/luci/;stok=STOK/api/misystem/status

            string result;
            HttpWebRequest wbRequest = (HttpWebRequest)WebRequest.Create(amirouterinfo.ConnectUrl + "//cgi-bin/luci/;stok=" + amirouterinfo.token + "/api/misystem/status");
            wbRequest.Method = "GET";
            HttpWebResponse wbResponse = (HttpWebResponse)wbRequest.GetResponse();
            using (Stream responseStream = wbResponse.GetResponseStream())
            {
                using (StreamReader sReader = new StreamReader(responseStream))
                {
                    result = sReader.ReadToEnd();
                }
            }
            return result.IndexOf("Invalid token") != -1 ? false : true;
        }
        public void UpdateLocalRouterBaseKey()
        {
            string result;
            HttpWebRequest httpRequest = (HttpWebRequest)WebRequest.Create(amirouterinfo.ConnectUrl + "/cgi-bin/luci/web");
            httpRequest.Method = "GET";
            HttpWebResponse wbResponse = (HttpWebResponse)httpRequest.GetResponse();
            using (Stream responseStream = wbResponse.GetResponseStream())
            {
                using (StreamReader sReader = new StreamReader(responseStream))
                {
                    result = sReader.ReadToEnd();
                }
            }
            amirouterinfo.key = result.IndexOf("key: '") != -1 ? result.Substring(result.IndexOf("key: '") + 6, result.IndexOf("',", result.IndexOf("key: '") + 6) - result.IndexOf("key: '") - 6) : null;
            amirouterinfo.iv = result.IndexOf("iv: '") != -1 ? result.Substring(result.IndexOf("iv: '") + 5, result.IndexOf("',", result.IndexOf("iv: '") + 5) - result.IndexOf("iv: '") - 5) : null;
            amirouterinfo.devicemac = result.IndexOf("var deviceId = '") != -1 ? result.Substring(result.IndexOf("var deviceId = '") + 16, result.IndexOf("';", result.IndexOf("var deviceId = '") + 16) - result.IndexOf("var deviceId = '") - 16) : null;
            amirouterinfo.Name = result.IndexOf("<div class=\"rtname\">") != -1 ? result.Substring(result.IndexOf("<div class=\"rtname\">") + 20, result.IndexOf("</div> -->", result.IndexOf("<div class=\"rtname\">") + 20) - result.IndexOf("<div class=\"rtname\">") - 20).Trim() : null;
            amirouterinfo.Device_ID = result.IndexOf("deviceId: '") != -1 ? result.Substring(result.IndexOf("deviceId: '") + 11, result.IndexOf("'", result.IndexOf("deviceId: '") + 11) - result.IndexOf("deviceId: '") - 11) : null;
            amirouterinfo.RomVersion = result.IndexOf("romVersion: '") != -1 ? result.Substring(result.IndexOf("romVersion: '") + 13, result.IndexOf("'", result.IndexOf("romVersion: '") + 13) - result.IndexOf("romVersion: '") - 13) : null;
            amirouterinfo.RomChannel = result.IndexOf("romChannel: '") != -1 ? result.Substring(result.IndexOf("romChannel: '") + 13, result.IndexOf("'", result.IndexOf("romChannel: '") + 13) - result.IndexOf("romChannel: '") - 13) : null;
            amirouterinfo.HardWareVersion = result.IndexOf("hardwareVersion: '") != -1 ? result.Substring(result.IndexOf("hardwareVersion: '") + 18, result.IndexOf("'", result.IndexOf("hardwareVersion: '") + 18) - result.IndexOf("hardwareVersion: '") - 18) : null;
            amirouterinfo.ccode = result.IndexOf("ccode = '") != -1 ? result.Substring(result.IndexOf("ccode = '") + 9, result.IndexOf("'", result.IndexOf("ccode = '") + 9) - result.IndexOf("ccode = '") - 9) : null;
        }

        private string GetMiRouterinfo(string info_name)
        {
            string result;
            HttpWebRequest httpRequest = (HttpWebRequest)WebRequest.Create(amirouterinfo.ConnectUrl + $"/cgi-bin/luci/;stok={amirouterinfo.token}/api/{info_name}");
            httpRequest.Method = "GET";
            HttpWebResponse wbResponse = (HttpWebResponse)httpRequest.GetResponse();
            using (Stream responseStream = wbResponse.GetResponseStream())
            {
                using (StreamReader sReader = new StreamReader(responseStream))
                {
                    result = sReader.ReadToEnd();
                }
            }
            if (result.IndexOf("Invalid token") != -1)
            {
                throw new Exception("Invalid token");
            }
            return result;
        }
        private string SetMiRouterinfo(string info_name,string parm)
        {
            //http://192.168.31.1/cgi-bin/luci/;stok=/api/misystem/set_router_name?name=Mane_Gongbei_Home&locale=%E5%AE%B6
            string result;
            HttpWebRequest wbRequest = (HttpWebRequest)WebRequest.Create(amirouterinfo.ConnectUrl + "/cgi-bin/luci/;stok=" + amirouterinfo.token + "/api/"+info_name+"?"+parm);
            wbRequest.Method = "GET";
            HttpWebResponse wbResponse = (HttpWebResponse)wbRequest.GetResponse();
            using (Stream responseStream = wbResponse.GetResponseStream())
            {
                using (StreamReader sReader = new StreamReader(responseStream))
                {
                    result = sReader.ReadToEnd();
                }
            }
            if (result.IndexOf("Invalid token") != -1)
            {
                throw new Exception("Invalid token");
            }
            return result;
        }

        #region base misystem api

        #region GetArea
        public string SysGetRouterName()
        {
            return GetMiRouterinfo("misystem/router_name");
        }
        public string SysGetStatus()
        {
            return GetMiRouterinfo("misystem/status") ;
        }
        public string SysGetBandwidthTest()
        {
            return GetMiRouterinfo("misystem/bandwidth_test?history=1");
        }
        public string SysGetDeviceList()
        {
            return GetMiRouterinfo("misystem/devicelist");
        }
        public string SysGetDeviceDetail()
        {
            return GetMiRouterinfo("misystem/device_detail");
        }
        public string SysGetDeviceInfo()
        {
            return GetMiRouterinfo("misystem/device_info");
        }
        public string SysGetMessages()
        {
            return GetMiRouterinfo("misystem/messages");
        }
        public string SysGetPppoeStatus()
        {
            return GetMiRouterinfo("misystem/pppoe_status");
        }
        public string SysGetOtaInfo()
        {
            return GetMiRouterinfo("misystem/ota");
        }
        public string SysGetChannelResult()
        {
            return GetMiRouterinfo("misystem/channel_scan_result");
        }
        public string SysGetRouterCommonStatus()
        {
            return GetMiRouterinfo("misystem/router_common_status");
        }
        public string SysGetQosInfo()
        {
            return GetMiRouterinfo("misystem/qos_info");
        }
        public string SysGetQosDeviceinfo()
        {
            return GetMiRouterinfo("misystem/qos_dev_info");
        }
        public string SysGetQosNewInfo()
        {
            return GetMiRouterinfo("misystem/qos_info_new");
        }
        public string SysGetDiskInfo()
        {
            return GetMiRouterinfo("misystem/getDiskinfo");
        }
        public string SysGetDiskIOData()
        {
            return GetMiRouterinfo("misystem/io_data");
        }
        public string SysGetDiskCheckStatus()
        {
            return GetMiRouterinfo("misystem/check_status");
        }
        public string SysGetDiskRepairStatus()
        {
            return GetMiRouterinfo("misystem/repair_status");
        }
        public string SysGetDiskFormatStatus()
        {
            //--status
            //-- 0:未格式化
            //-- 1:正在格式化
            //-- 2:格式化成功
            //-- 3:格式化失败
            return GetMiRouterinfo("misystem/disk_format_status");
        }
        public string SysGetDiskStatus()
        {

            return GetMiRouterinfo("misystem/disk_status");
        }
        public string SysGetDiskSmartCtl()
        {
            return GetMiRouterinfo("misystem/disk_smartctl");
        }
        public string SysGetSpeedTestResult()
        {
            return GetMiRouterinfo("misystem/speed_test_result");
        }
        public string SysGetAntiRubStatus()
        {
            return GetMiRouterinfo("misystem/arn_status");
        }
        public string SysGetAntiRubRecords()
        {
            return GetMiRouterinfo("misystem/arn_records");
        }
        public string SysGetEcosInfo(string mac)
        {
            return SetMiRouterinfo("misystem/ecos_info", $"mac={mac}");
        }
        public string SysGetEcosUpgrade(string mac)
        {
            return SetMiRouterinfo("misystem/ecos_upgrade", $"mode={mac}");
        }
        public string SysGetEcosUpgradeStatus(string mac)
        {
            return SetMiRouterinfo("misystem/ecos_upgrade_status", $"mac={mac}");
        }
        public string SysGetHwnatStatus()
        {
            return GetMiRouterinfo("misystem/hwnat_status");
        }
        public string SysGetHttpHijackStatus()
        {
            return GetMiRouterinfo("misystem/http_status");
        }
        public string SysGetlsusb()
        {
            return GetMiRouterinfo("misystem/lsusb");
        }
        public string SysGetToolbarStatus()
        {
            return GetMiRouterinfo("misystem/tb_info");
        }
        public string SysGetNetacctlStatus(string mac)
        {
            return SetMiRouterinfo("misystem/netacctl_status", $"mac={mac}");
        }
        public string SysGetRemoteWebAccessStatus()
        {
            return GetMiRouterinfo("misystem/web_access_info");
        }
        public string SysGetSmartVpnInfo()
        {
            return GetMiRouterinfo("misystem/smartvpn_info");
        }
        public string SysGetMiVPNInfo()
        {
            return GetMiRouterinfo("misystem/mi_vpn_info");
        }
        public string SysGetTime()
        {
            return GetMiRouterinfo("misystem/sys_time");
        }
        public string SysGetArnSecurityInfo()
        {
            return GetMiRouterinfo("misystem/arn_security");
        }
        public string SysGetUsbMode3()
        {
            return GetMiRouterinfo("misystem/get_usb_u3");
        }
        public string SysGetExtendWifiScanList()
        {
            return GetMiRouterinfo("misystem/extendwifi_scanlist");
        }
        public string SysGetElink()
        {
            return GetMiRouterinfo("misystem/get_elink");
        }
        public string SysGetDevBsdInfo(string mac)
        {
            return SetMiRouterinfo("misystem/get_dev_bsd", $"mac={mac}");
        }
        #endregion

        #region Void area
        public string SysDiskInit()
        {
            return GetMiRouterinfo("misystem/disk_init");
        }
        public string SysDiskFormat()
        {
            return GetMiRouterinfo("misystem/disk_format");
        }
        public string SysDiskFormatAsync()
        {
            return GetMiRouterinfo("misystem/disk_format_async");
        }
        public string SysResolveIpConflict()
        {
            return GetMiRouterinfo("misystem/r_ip_conflict");
        }
        #endregion

        #region Service Area
        public string SysStartChannelScan()
        {
            return GetMiRouterinfo("misystem/channelScanStart");
        }
        public string SysStartQosService()
        {
            return SetMiRouterinfo("misystem/qos_switch", $"on=1");
        }
        public string SysStartHwnatService()
        {
            return SetMiRouterinfo("misystem/hwnat_switch", $"on=1");
        }
        public string SysStartHttpHijackService()
        {
            return SetMiRouterinfo("misystem/http_switch", $"on=1");
        }
        public string SysStartDiskCheck()
        {
            return GetMiRouterinfo("misystem/disk_check");
        }
        public string SysStartDiskRepair()
        {
            return GetMiRouterinfo("misystem/disk_repair");
        }
        public string SysStartBackupLog()
        {

            return GetMiRouterinfo("misystem/sys_log");
        }
        public string SysStartSpeedTest()
        {
            return GetMiRouterinfo("misystem/speed_test");
        }
        public string SysStartMiVPN()
        {
            return SetMiRouterinfo("misystem/mi_vpn", $"open=1");
        }
        public string SysStartIperfService()
        {
            return SetMiRouterinfo("misystem/iperf", $"switch=1");
        }
        public string SysStartDebugMode(string verifycode,string password)
        {
            return SetMiRouterinfo("misystem/debug", $"open=1&verifycode={verifycode}&password={password}");
        }
        
        public string SysStopQosService()
        {
            return SetMiRouterinfo("misystem/qos_switch", $"on=0");
        }
        public string SysStopPppoeService()
        {
            return GetMiRouterinfo("misystem/pppoe_stop");
        }
        public string SysStopDebugMode()
        {
            return SetMiRouterinfo("misystem/debug", $"open=0");
        }
        public string SysStopHwnatService()
        {
            return SetMiRouterinfo("misystem/hwnat_switch", $"on=0");
        }
        public string SysStopHttpHijackService()
        {
            return SetMiRouterinfo("misystem/http_switch", $"on=0");
        }
        public string SysStopIperfService()
        {
            return SetMiRouterinfo("misystem/iperf", $"switch=0");
        }
        public string SysStopMiVPN()
        {
            return SetMiRouterinfo("misystem/mi_vpn", $"open=0");
        }
        public string SysRestartQosService()
        {
            return GetMiRouterinfo("misystem/active");
        }
        public string SysEnableRouterLed()
        {
            return SetMiRouterinfo("misystem/led", $"on=1");
        }
        public string SysDisableRouterLed()
        {
            return SetMiRouterinfo("misystem/led", $"on=0");
        }
        public string SysEnableConfigUpload()
        {
            return SetMiRouterinfo("misystem/conf_upload_enable", $"enable=1");
        }
        public string SysDisableConfigUpload()
        {
            return SetMiRouterinfo("misystem/conf_upload_enable", $"enable=0");
        }
        public string SysEnableElink()
        {
            return SetMiRouterinfo("misystem/set_elink", $"enable=1");
        }
        public string SysDisableElink()
        {
            return SetMiRouterinfo("misystem/set_elink", $"enable=0");
        }
        public string SysEnableUsbMode3()
        {
            return SetMiRouterinfo("misystem/usb_u3", $"enable=1");
        }
        public string SysDisableUsbMode3()
        {
            return SetMiRouterinfo("misystem/usb_u3", $"enable=0");
        }
        #endregion

        #region Setting Area
        public string SysSetRouterName(string name, string local)
        {
            return SetMiRouterinfo("misystem/set_router_name", "name="+name+ "&locale="+ local);
        }
        public string SysSetWan(string proto, string username, string password, string service)
        {
            return SetMiRouterinfo("misystem/set_wan", $"proto={proto}&username={username}&password={password}&service={service}");
        }
        public string SysSetOtaInfo(string auto,string time,string plugin)
        {
            return SetMiRouterinfo("misystem/set_ota", $"auto={auto}&time={time}&plugin={plugin}");
        }
        public string SysSetChannel(string channel1, string channel2)
        {
            return SetMiRouterinfo("misystem/set_channel", $"channel1={channel1}&channel2={channel2}");
        }
        public string SysSetQosDevicesInfo(string mac, string upload,string download)
        {
            return SetMiRouterinfo("misystem/qos_set_dev_info", $"mac={mac}&upload={upload}&download={download}");
        }
        public string SysSetQosSwitcher(bool status)
        {
            return SetMiRouterinfo("misystem/qos_switch", $"on={Convert.ToInt32(status).ToString()}");
        }
        public string SysSetQosMode(string mode)
        {
            return SetMiRouterinfo("misystem/qos_mode", $"mode={mode}");
        }
        public string SysSetQosLimit(string mac,string mode,string upload,string download)
        {
            return SetMiRouterinfo("misystem/qos_limit", $"mac={mac}&mode={mode}&upload={upload}&download={download}");
        }
        public string SysSetQosLimitFlag(string mac,string flag)
        {
            /// <param name="flag">on or off</param>
            return SetMiRouterinfo("misystem/qos_limit_flag", $"mac={mac}&flag={flag}");
        }
        public string SysSetQosLimits(string mode, string data)
        {
            /// <param name="flag">on or off</param>
            return SetMiRouterinfo("misystem/qos_limits", $"mode={mode}&data={data}");
        }
        public string SysSetQosLimitOff(string mac)
        {
            return SetMiRouterinfo("misystem/qos_offlimit", $"mac={mac}");
        }
        public string SysSetBand(string upload,string download ,string manual)
        {
            return SetMiRouterinfo("misystem/set_band", $"upload={upload}&download={download}&manual={manual}");
        }
        public string SysSetAntiRubSwitcher(string open, string level, string mode)
        {
            //mode = 0 or 1
            return SetMiRouterinfo("misystem/arn_switch", $"open={open}&level={level}&mode={mode}");
        }
        public string SysSetAntiRubIgnore(string mac, string key)
        {
            return SetMiRouterinfo("misystem/arn_ignore", $"mac={mac}&key={key}");
        }
        public string SysSetEcosSwitcher(string mac, string key, bool on)
        {
            return SetMiRouterinfo("misystem/ecos_switch", $"mac={mac}&key={key}&on={Convert.ToInt32(on).ToString()}");
        }
        public string SysSetNetacctl(string mac, string mode, bool enable)
        {
            return SetMiRouterinfo("misystem/netacctl_set", $"mac={mac}&mode={mode}&enable={Convert.ToInt32(enable).ToString()}");
        }
        public string SysSetRemoteWebAccess(string open, string mac, bool opt)
        {
            return SetMiRouterinfo("misystem/web_access_opt", $"open={Convert.ToInt32(open).ToString()}&mac={mac}&opt={Convert.ToInt32(opt).ToString()}");
        }
        public string SysSetSmartVPNSwitcher(string enable, string mode)
        {
            return SetMiRouterinfo("misystem/smartvpn_switch", $"enable={Convert.ToInt32(enable).ToString()}&mode={mode}");
        }
        public string SysSetSmartVPNUrl(string url, string urls, bool opt)
        {
            return SetMiRouterinfo("misystem/smartvpn_url", $"url={url}&urls={urls}&opt={Convert.ToInt32(opt).ToString()}");
        }
        public string SysSetSmartVPNMac(string macs, bool opt)
        {
            return SetMiRouterinfo("misystem/smartvpn_url", $"macs={macs}&opt={Convert.ToInt32(opt).ToString()}");
        }
        public string SysSetTime(string time, string timezone, string index)
        {
            return SetMiRouterinfo("misystem/arn_switch", $"time={time}&timezone={timezone}&index={index}");
        }
        public string SysSetDevBsdInfo(string mac, string mode)
        {
            return SetMiRouterinfo("misystem/set_dev_bsd", $"mac=mac&mode={mode}");
        }
        public string SysSetExtendWifiConnect(string ssid,string encryption,string enctype,string password,string channel,string band)
        {
            return SetMiRouterinfo("misystem/extendwifi_connect", $"ssid={ssid}&encryption={encryption}&enctype={enctype}&=password={password}&=channel{channel}&band={band}");
        }
        #endregion

        #region other Area
        public string SysChangeRemotePassword(string newPwd)
        {
            return SetMiRouterinfo("misystem/password", $"newPwd={newPwd}");
        }
        public string isMiWiFi()
        {
            return GetMiRouterinfo("misystem/miwifi");
        }
        #endregion

        #endregion base misystem api

        #region xqsystem 
        public string XQSysReboot()
        {
            return SetMiRouterinfo("xqsystem/reboot", $"client=web");
        }

        #endregion


    }


}
