# heartrate_webui
支持BLE心率设备监测的webui，带有一个方便obs等软件导入直播源的心率组件。目前只做了小米手环优化

<img width="593" height="375" alt="image" src="https://github.com/user-attachments/assets/6cbda132-88c6-4399-932d-799950b33b4f" />

测试、优化设备为Mi Smart Band 6，其他设备原理上相同，可能需要一定自定义。

使用会在运行目录下创建`heartrate.db`用作数据持久化，请确保足够的写入权限。

## 使用方法

0. 小米手环请在APP设备设置中开启`运动心率广播`并随意开启一个运动。获取数据期间需要保持运动状态。其他设备请自行研究类似功能。

1. 环境准备

```
python >=3.10
```

2. 安装依赖

```
pip install fastapi uvicorn websockets bleak
```

3. 运行程序

```
python heartrate_webui.py
```

4. 访问WebUI

```
http://127.0.0.1:8000
```

5. 填入设备MAC

从设备的设置等位置获取到设备的蓝牙MAC号，并填入页面下方`监听捕获 MAC`框中，随后点击应用设置。

- [可选]访问设备扫描探测器

```
http://127.0.0.1:8000/scan
```

- [可选]访问心率组件

```
http://127.0.0.1:8000/live
```
