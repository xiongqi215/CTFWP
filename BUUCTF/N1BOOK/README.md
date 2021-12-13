# [第一章 web入门]粗心的小李

根据题目提示，是一道git泄露题，直接上工具GitHacker下载git文件

![](pic/git_01.png)
![](pic/git_02.png)

访问index.html，得到flag
![](pic/git_03.png)


#[第一章 web入门]常见的搜集

敏感文件泄露，web中常见的敏感文件包括：

> 
- rbots.txt
- readme.txt/md
- www.zip/rar/tar：网站备份文件
- 中间件的banner信息，暴露中间件版本或框架版本
- gedit备份文件：后缀为~
- vim备份文件: .文件名.swp
- 未完待续。。。。

本题：
解题
发现robots,得到提示flag1_is_her3_fun.txt访问该文件，得到FALG上半部分：
![](pic/sf1.png)

发现index.php~，得到第二部部分flag: s_v3ry_im
![](pic/sf2.png)

发现.index.php.swp，下载后通过命令还原
![](pic/sf3.png)

```shell
touch index.php --先创建index.php文件
vim -r index.php --还原文件
```
![](pic/sf4.png)


