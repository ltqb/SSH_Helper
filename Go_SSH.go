package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/pkg/sftp"
)

type Cli struct {
	IP         string      //IP地址
	Username   string      //用户名
	Password   string      //密码
	Port       int         //端口号
	client     *ssh.Client //ssh客户端
	LastResult string      //最近一次Run的结果
}

//创建命令行对象
//@param ip IP地址
//@param username 用户名
//@param password 密码
//@param port 端口号,默认22
func New(ip string, username string, password string, port ...int) *Cli {
	cli := new(Cli)
	cli.IP = ip
	cli.Username = username
	cli.Password = password
	if len(port) <= 0 {
		cli.Port = 22
	} else {
		cli.Port = port[0]
	}
	return cli
}

//执行shell
//@param shell shell脚本命令
func (c Cli) Run(shell string) (string, error) {
	if c.client == nil {
		if err := c.connect(); err != nil {
			return "", err
		}
	}
	session, err := c.client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	buf, err := session.CombinedOutput(shell)

	c.LastResult = string(buf)
	return c.LastResult, err
}

//连接
func (c *Cli) connect() error {
	config := ssh.ClientConfig{
		User: c.Username,
		Auth: []ssh.AuthMethod{ssh.Password(c.Password)},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
		Timeout: 10 * time.Second,
	}
	addr := fmt.Sprintf("%s:%d", c.IP, c.Port)
	sshClient, err := ssh.Dial("tcp", addr, &config)
	if err != nil {
		return err
	}
	c.client = sshClient
	return nil
}

//执行带交互的命令
func (c *Cli) RunTerminal(shell string, stdout, stderr io.Writer) error {
	if c.client == nil {
		if err := c.connect(); err != nil {
			return err
		}
	}
	session, err := c.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := terminal.MakeRaw(fd)
	if err != nil {
		panic(err)
	}
	defer terminal.Restore(fd, oldState)

	session.Stdout = stdout
	session.Stderr = stderr
	session.Stdin = os.Stdin

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		panic(err)
	}
	// Set up terminal modes
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // enable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	// Request pseudo terminal
	if err := session.RequestPty("xterm-256color", termHeight, termWidth, modes); err != nil {
		return err
	}

	session.Run(shell)
	return nil
}

func Decode(data string, BASE64Table string) string {
	coder := base64.NewEncoding(BASE64Table)
	result, _ := coder.DecodeString(data)
	return *(*string)(unsafe.Pointer(&result))
}

func readLine(r *bufio.Reader) (string, error) {
	line, isprefix, err := r.ReadLine()
	for isprefix && err == nil {
		var bs []byte
		bs, isprefix, err = r.ReadLine()
		line = append(line, bs...)
	}
	return string(line), err
}

func ReadLine(filename string) map[string]string {
	f, _ := os.Open(filename)
	defer f.Close()
	r := bufio.NewReader(f)
	info := make(map[string]string)
	for {
		var a []string

		str, err := readLine(r)
		if err != nil {
			break
		} else {
			a = strings.Split(str, " ")
			info[a[0]] = a[1] + " " + a[2]
		}
	}
	return info
}

func RunCommandOnOne(shell string, ip string, username string, password string, port int, cha1 chan string) (string, error) {
	basetable := "IJjkKLMNO567PWQX12RV3YZaDEFGbcdefghiABCHlSTUmnopqrxyz04stuvw89+/"
	cli := New(ip, username, Decode(password, basetable), port)
	output, err := cli.Run(shell)
	if err != nil {
		cha1 <- err.Error()
	} else {
		cha1 <- output
	}
	return output, err
}
func sftpconnect(user, password, host string, port int) (*sftp.Client, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		sshClient    *ssh.Client
		sftpClient   *sftp.Client
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))

	clientConfig = &ssh.ClientConfig{
		User:    user,
		Auth:    auth,
		Timeout: 30 * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)

	if sshClient, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	// create sftp client
	if sftpClient, err = sftp.NewClient(sshClient); err != nil {
		return nil, err
	}

	return sftpClient, nil
}

func WriteFiles(filepath string, context string) {
	data := []byte(context)
	if ioutil.WriteFile(filepath, data, 0644) == nil {
		fmt.Println("write success")
	}
}

func main() {

	file := "./" + time.Now().Format("20180102") + ".log"
	logFile, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0766)
	if nil != err {
		panic(err)
	}
	loger := log.New(logFile, "[Info] ", log.Ldate|log.Ltime|log.Lshortfile)
	loger.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	var ip string
	var username string
	var password string
	var port int
	var hostFile string
	var shell string
	var src string
	var dest string
	//var forks int
	flag.StringVar(&ip, "ip", "", "remote ip address to ssh")
	flag.StringVar(&username, "user", "", "remote host user to ssh")
	flag.StringVar(&password, "password", "", "the password to ssh remote")
	flag.IntVar(&port, "port", 22, "remote port  to ssh")
	flag.StringVar(&hostFile, "file", "", "hosts config to ssh")
	//flag.BoolVar(&tty,"tty",false,"ssh tty")
	flag.StringVar(&shell, "command", "", "ssh remote to run shell ")
	flag.StringVar(&src, "src", "", "scp src path  to remote")
	flag.StringVar(&dest, "dest", "", "scp dest path to remote ")
	//flag.IntVar(&forks, "forks", 1, "the number ssh to remotes concurrently  ")
	flag.Parse()

	if len(ip) > 0 && len(username) > 0 && len(password) > 0 && len(shell) > 0 && len(hostFile) == 0 && len(src)==0 &&len(dest)==0 {
		cha1 := make(chan string, 10)
		//cli := New(ip, username, Decode(password, basetable), port)
		output, err := RunCommandOnOne(shell, ip, username, password, port, cha1)
		if err == nil {
			loger.Println(ip, "EXEC : \""+shell+"\"")
			loger.Println(ip, "RESULT : \n", output)
		} else {
			loger.Println("ERROR :", err)
		}
		//fmt.Printf("%v\n%v", output, err)

	} else if len(hostFile) > 0 && len(shell) > 0 {
		hostInfo := make(map[string]string)
		hostInfo = ReadLine(hostFile)
		chs := make(chan string, len(hostInfo))
		for k, v := range hostInfo {
			a := strings.Split(v, " ")
			//fmt.Println(len(hostInfo))kk
			fmt.Println(k, "result: ")
			go RunCommandOnOne(shell, k, a[0], a[1], port, chs)
			//fmt.Println(<-chs)
			loger.Println(k, "EXEC : \""+shell+"\"")
			loger.Println(k, "RESULT : \n", <-chs)

		}
		time.Sleep(time.Second)
	} else if len(shell)==0 && len(hostFile) == 0 &&len(src) > 0 && len(dest) > 0 {
		basetable := "IJjkKLMNO567PWQX12RV3YZaDEFGbcdefghiABCHlSTUmnopqrxyz04stuvw89+/"

		var (
			sftpClient *sftp.Client
		)

		// 这里换成实际的 SSH 连接的 用户名，密码，主机名或IP，SSH端口
		sftpClient, err = sftpconnect(username, Decode(password,basetable), ip, port)
		if err != nil {
			fmt.Println("error connect")
			log.Fatal(err)
		}
		defer sftpClient.Close()

		// 用来测试的本地文件路径 和 远程机器上的文件夹
		var localFilePath = src
		var remoteDir = dest
		srcFile, err := os.Open(localFilePath)
		if err != nil {
			log.Fatal(err)
		}
		defer srcFile.Close()

		//var remoteFileName = path.Base(localFilePath)
		//dstFile, err := sftpClient.Create(path.Join(remoteDir, remoteFileName))
		dstFile, err := sftpClient.Create(remoteDir)
		if err != nil {
			log.Fatal(err)
		}
		defer dstFile.Close()

		buf := make([]byte, 1024)
		for {
			n, _ := srcFile.Read(buf)
			if n == 0 {
				break
			}
			dstFile.Write(buf[0:n])
		}

		fmt.Println(src+" copy to "+ip+":"+ dest+ " finished!")


	} else {
		flag.PrintDefaults()
		fmt.Println("  ")
		fmt.Println("EXAMPLES:")
		fmt.Println("# SSH Remote to Run Shell")
		fmt.Println("# ssh_helper --ip=192.168.1.1 --user=root --password=\"123456\" --port=22 --command=\"df -h\"")
		fmt.Println("  ")
		fmt.Println("# SSH Remotes to Run Shell From Hosts Config")
		fmt.Println("# ssh_helper --file=\"hostConfig.ini\" --command=\"df -h\"")
		fmt.Println("  ")
		fmt.Println("# Copy File to Remote Like Scp")
		fmt.Println("# ssh_helper --ip=192.168.1.1 --user=root --password=\"123456\" --port=22  --src=\"/123.txt\" --dest=\"/123.txt\"")
	}

}
