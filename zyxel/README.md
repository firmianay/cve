# VMG5153-B30B zhttpd buffer overflow

router: https://www.zyxel.com/us/en/support/SupportLandingSR.shtml?c=us&l=en&kbid=M-02333&md=VMG5313-B30B#searchZyxelTab1

```html
security <security@zyxel.com.tw>	September 18, 2020 9:55 AM
收件人：杨超 <firmianay@gmail.com>
抄送：security <security@zyxel.com.tw>

HI 楊超,
感謝您的回覆。關於CVE ID部分，因為漏洞是由您發現，建議由您申請會較為合適。若有任何問題，請再與我們聯絡，再次感謝您直接通報給Zyxel。

HI Yang Chao,
Thanks for your reply. Regarding the CVE ID part, because the vulnerability was discovered by you, it is more appropriate to apply for it. If you have any questions, please contact us again, thank you again for reporting directly to Zyxel.




杨超 <firmianay@gmail.com>	September 17, 2020 8:00 PM
收件人：security <security@zyxel.com.tw>

感谢回复，其实我是看过这篇文章（https://blog.somegeneric.ninja/Zyxel_VMG5153_B30B）后才下载的固件，那么这个问题是否也可以分配一个CVE呢？

Thanks for the reply. Actually, I downloaded the firmware after reading this article (https://blog.somegeneric.ninja/Zyxel_VMG5153_B30B), so can I assign a CVE to this question?




RE: VMG5153-B30B 缓冲区溢出漏洞
3 封邮件
security <security@zyxel.com.tw>	September 17, 2020 6:20 PM
收件人：杨超 <firmianay@gmail.com>
抄送：security <security@zyxel.com.tw>

Hi楊超,
再次感謝您的通報，經內部驗證後確認存在有緩衝區溢出問題，但在VMG5313-B30B的原廠設定中，HTTP 遠端連線預設為關閉， 況且產品本身有認證與隨機產生會話密鑰(session key) 的機制，因此風險較低。且VMG5313-B30B系列機種已EOL，根據產品EOL作業程序，我們將不再提供正式修補程式。謝謝!

Hi Yang Chao,
Thank you again for your notification. After internal verification, it is confirmed that there is a buffer overflow problem. However, in the original factory setting of VMG5313-B30B, the HTTP remote connection is closed by default, and the product itself has authentication and randomly generated session keys (session key) mechanism, so the risk is low. In addition, VMG5313-B30B series models have been EOL. According to the product EOL operating procedures, we will no longer provide official patches. Thank you!

Regards,
Zyxel Security Team




From: security
Sent: Thursday, September 03, 2020 10:59 AM
To: 杨超 <firmianay@gmail.com>
Cc: security <security@zyxel.com.tw>
Subject: RE: VMG5153-B30B 缓冲区溢出漏洞

Hi楊超,
感謝您的通報，我們會請相關團隊進行驗證，有任何進一步消息再與您聯繫，謝謝。

Hi Yang Chao,
Thank you for your notification. We will ask the relevant team to verify and contact you if we have any further information. Thank you.

Regards,
Zyxel Security Team




From: 杨超 [mailto:firmianay@gmail.com]
Sent: Wednesday, September 02, 2020 4:51 PM
To: security <security@zyxel.com.tw>
Subject: VMG5153-B30B 缓冲区溢出漏洞

你好，我在 VMG5313-B30B_5.11(ABCU.1)C0 中发现一个疑似缓冲区溢出，位于 zhttpd 程序的 FUN_00405218，该函数用于导入本地CA证书，URI 构造应该类似 “/cgi-bin/Certificates?action=import_local&priv=xxxxxxxx”，由于程序采用 while 的方式寻找字符串“xxxxxxxx”的结尾（&、?、\0），然后直接与字符串开头相减作为 strncpy 函数的长度参数，如果字符串过长，可能导致溢出。
遗憾的是我没有真实设备进行测试，但我非常相信这个漏洞的存在，所以先发了这封邮件。期待你们的回复。

Hello, I found a suspected buffer overflow in VMG5313-B30B_5.11(ABCU.1)C0, located in FUN_00405218 of the zhttpd program. This function is used to import local CA certificates. The URI structure should be similar to "/cgi-bin/Certificates ?action=import_local&priv=xxxxxxxx", because the program uses the while method to find the end of the string "xxxxxxxx" (&,?,\0), and then directly subtract from the beginning of the string as the length parameter of the strncpy function. Long and may cause overflow.
Unfortunately, I do not have real equipment for testing, but I am very confident that this vulnerability exists, so I sent this email first. Looking forward to your reply.

int FUN_00405218(int param_1) {
  bool bVar1;
  bool bVar2;
  char *__haystack;
  int iVar3;
  int iVar4;
  undefined4 local_450;
  char *local_44c;
  char *local_448;
  int local_444;
  undefined4 local_42c;
  undefined4 local_428;
  undefined4 local_424;
  undefined4 local_420;
  undefined4 local_41c;
  undefined local_418;
  char local_414 [1028];
  
  bVar1 = false;
  bVar2 = false;
  local_42c = 0;
  local_428 = 0;
  local_424 = 0;
  local_420 = 0;
  local_41c = 0;
  local_418 = 0;
  memset(local_414,0,0x400);
  local_444 = 1;
  __haystack = (char *)cg_http_request_geturi(param_1);
  local_44c = strstr(__haystack,"?action=import_local");
  if (local_44c == (char *)0x0) {
    local_44c = strstr(__haystack,"?action=import_ca");
    if (local_44c != (char *)0x0) {
      bVar1 = true;
      local_450 = 0;
    }
  }
  else {
    bVar2 = true;
    local_450 = 1;
  }
  if ((bVar1) || (bVar2)) {
    if (bVar2) {
      puts("Certificate Import: action=import_local, start to parse data...");
      __haystack = strstr(local_44c + 0x14,"&priv=");
      if (__haystack != (char *)0x0) {
        local_44c = local_44c + 0x1a;
        local_448 = local_44c;
        <b>while (((*local_448 != '&' && (*local_448 != '?')) && (*local_448 != '\0'))) {</b>
          local_448 = local_448 + 1;
        }
        printf("Certificate Import: find &priv value, start=%d, end=%d.\n",local_44c,local_448);
        if (local_448 != local_44c) {
          <b>strncpy((char *)&local_42c,local_44c,(size_t)(local_448 + -(int)local_44c));</b>
          printf("Certificate Import: find private key password %s.\n",&local_42c);
        }
      }
    }
...

```
