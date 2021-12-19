# 常见任意文件读取利用
## 语言相关
### PHP
- file_get_contents()、file()、fopen()
- 执行系统命令：system()、exec()
- 伪协议 php://filter/convert.base64-encode/resource=flag 等
- 文件包含：include()、require()、include_once()、require_once()等

### python
- open()函数
- flask 模板注入

### Java
- FileInputStream、XXE 文件读取。
- Spring Cloud Config Server路径穿越与任意文件读取漏洞（CVE-2019-3799）
- Jenkins任意文件读取漏洞（CVE-2018-1999002）等

### Node
- Node.js的express任意文件读取漏洞（CVE-2017-14849)
- 模板注入、代码注入

## 中间件配置

### Nginx
``` 
Location /static{
Alias /home/myapp/static/;
}
```
- 请求路径如果/static…/，将造成目录穿越漏洞



## 读取目录目标

- /etc：/etc目录下多是各种应用或系统配置文件，所以其下的文件是进行文件读取的首要目标。
- /etc/passwd：/etc/passwd文件是Linux系统保存用户信息及其工作目录的文件，权限是所有用户/组可读，一般被用作Linux系统下文件读取漏洞存在性判断的基准。读到这个文件我们就可以知道系统存在哪些用户、他们所属的组是什么、工作目录是什么。
- /etc/shadow：/etc/shadow是Linux系统保存用户信息及（可能存在）密码（hash）的文件，权限是root用户可读写、shadow组可读。所以一般情况下，这个文件是不可读的。
- /etc/apache2/*：是Apache配置文件，可以获知Web目录、服务端口等信息。CTF有些题目需要参赛者确认Web路径。
- etc/nginx/*：是Nginx配置文件（Ubuntu等系统），可以获知Web目录、服务端口等信息。
- /etc/apparmor(.d)/*：是Apparmor配置文件，可以获知各应用系统调用的白名单、黑名单。例如，通过读配置文件查看MySQL是否禁止了系统调用，从而确定是否可以使用UDF（User Defined Functions）执行系统命令。
- /etc/(cron.d/*|crontab)：定时任务文件。有些CTF题目会设置一些定时任务，读取这些配置文件就可以发现隐藏的目录或其他文件。
- /etc/environment：是环境变量配置文件之一。环境变量可能存在大量目录信息的泄露，甚至可能出现secret key泄露的情况。
- /etc/hostname：表示主机名。
- /etc/hosts：是主机名查询静态表，包含指定域名解析IP的成对信息。通过这个文件，参赛者可以探测网卡信息和内网IP/域名。
- /etc/issue：指明系统版本。
- /etc/mysql/*：是MySQL配置文件。
- /etc/php/*：是PHP配置文件。
- /proc目录：/proc目录通常存储着进程动态运行的各种信息，本质上是一种虚拟目录。
	- 目录下的cmdline可读出比较敏感的信息：/proc/[pid]/cmdline
	- 通过cwd命令可以直接跳转到当前目录:/proc/[pid]/cwd
	- 环境变量中可能存在secret_key，这时也可以通过environ进行读取：/proc/[pid]/environ
- 其他目录：
	- Nginx配置文件可能存在其他路径：/usr/local/nginx/conf/*
	- 日志文件：/var/log/*
	- Apache默认Web根目录：/var/www/html
	- PHP session目录：/var/lib/php(5)/sessions 可能泄露用户Session
- 用户目录：[user_dir_you_know]/.bash_history 历史命令执行
	- [user_dir_you_know]/.bashrc 部分环变量
	- [user_dir_you_know]/.ssh/id_rsa(.pub) ssh登录的私钥/公钥
	- [user_dir_you_know]/.viminfo vim的使用记录
