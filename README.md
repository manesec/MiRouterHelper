# MiRouterHelper
C# Library operation of XiaoMi Router


### Build Time:
2018-08-07

And We will add instructions later


### Test Successful Development:
小米路由器3(R3) 	

MiWiFi 开发版 2.27.110

### How to use?
1.You need to add References in your project.

```
MiRouterHelper mirouter = new MiRouterHelper("http://192.168.31.1");
MiRouterAPI m = new MiRouterAPI(mirouter.LoginToGetBaseKey("your_xiaomi_router_password"));
```
2.Use the function.

Example:

```
MiRouterHelper mirouter = new MiRouterHelper("http://192.168.31.1");
MiRouterAPI m = new MiRouterAPI(mirouter.LoginToGetBaseKey("your_xiaomi_router_password"));
Console.WriteLine(m.SysGetStatus());
Console.WriteLine(m.XQSysReboot());    //Reboot Xiaomi Router
mirouter.LoginOut();
```


### Development
1. [Visual Studio 2010] & [.NET Framework 4.0 Developer Pack] are required.
