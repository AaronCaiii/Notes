# 靶机无法获取ip解决方案
1. 打开linux进入到引导界面之后按e
![Img](../FILES/GetTargetIP/img-20220723000210.png)
![Img](../FILES/GetTargetIP/img-20220723000215.png)

2. 找到linux那一行, 修改参数
  - 分两种情况, 一种是没有ro
  - 一种是有ro
  - 有ro需要改成rw
  - 没ro直接在尾部加上rw
  - 然后再加上init=/bin/bash
如图所示😁
![Img](../FILES/GetTargetIP/img-20220723000415.png)
3. 然后ctrl+x保存后就会进入到root单用户界面
![Img](../FILES/GetTargetIP/img-20220723000442.png)
4. ip a查看一下网卡信息, 在此处为ens33, 具体以实际为准
![Img](../FILES/GetTargetIP/img-20220723000518.png)
5. vi /etc/network/interfaces修改网卡信息
  - 如果没有完成第二步操作将无法修改信息
  - 修改网卡参数(从allow改成auto)
  - 此处我是为了方便识别, 将eth0/eth1/ens33都加上了
![Img](../FILES/GetTargetIP/img-20220723000644.png)
```
auto eth0
iface eth0 inet dhcp
auto eth1
iface eth1 inet dhcp
auto ens33
iface ens33 inet dhcp
```
然后:wq保存退出
6. 最后exec /sbin/init
![Img](../FILES/GetTargetIP/img-20220723000852.png)
- 此处会显示Fail信息, 不用担心, 只不过是我刚刚加的网卡不在这个机器上而已
![Img](../FILES/GetTargetIP/img-20220723000932.png)

7. 再在kali上面扫描, 不出意外的话就已经有ip显示出来了