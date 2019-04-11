package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/spf13/viper"
)

var port = flag.Int("p", 9001, "Listen Port")
var Users = make(map[string]string)

func init() {
	viper.SetConfigFile("./user.yaml")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error Read User Config file: %v", err)
	}
	Users = viper.GetStringMapString("users")
}

func main() {
	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Start Listen on %s ......\n", addr)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Panicf("Error Listen on %s : %s", addr, err)
	}
	for {
		client, err := l.Accept()

		if err != nil {
			log.Printf("Error Accept Connection: %s\n", err)
			continue
		}

		go handleClientRequest(client)
	}

}

func handleClientRequest(c net.Conn) {
	if c == nil {
		return
	}
	defer c.Close()
	var b [1024]byte
	n, err := c.Read(b[:])
	if err != nil {
		log.Printf("[01]Error Read Connection from [%s]: %s", c.RemoteAddr(), err)
		return
	}

	// 支持socks5
	if b[0] == 0x05 {
		// 提示客户端需要用户名和密码认证
		c.Write([]byte{0x05, 0x02})

		// 读取客户端认证信息并认证
		n, err = c.Read(b[:])
		if err != nil {
			log.Printf("[02]Error Read Connection from [%s]: %s", c.RemoteAddr(), err)
			return
		}
		b0 := b[0]
		nameLens := int(b[1])
		name := string(b[2 : 2+nameLens])
		passLens := int(b[2+nameLens])
		pass := string(b[2+nameLens+1 : 2+nameLens+1+passLens])
		err := authUser(name, pass)
		if err != nil {
			// 认证不通过则记录日志并返回
			log.Printf("Login Failed : %s\n", err)
			c.Write([]byte{b0, 0xff})
			return
		}

		// 认证通过
		c.Write([]byte{b0, 0x00})

		// 读取客户端请求信息
		n, err = c.Read(b[:])
		if err != nil {
			log.Printf("[03]Error Read Connection from [%s]: %s", c.RemoteAddr(), err)
			return
		}

		// 解析请求地址
		var host, port string
		switch b[3] {
		case 0x01:
			host = net.IPv4(b[4], b[5], b[6], b[7]).String()
		case 0x03:
			host = string(b[5 : n-2])
		case 0x04:
			host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
		}
		port = strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))
		// 连接服务端
		server, err := net.Dial("tcp", net.JoinHostPort(host, port))
		if err != nil {
			log.Printf("Error Dial TCP: %s:%s", host, port)
			return
		}
		defer server.Close()
		log.Printf("%s Connected to %s:%s", name, host, port)
		// 通知客户端连接成功
		c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

		// 复制转发流量
		go io.Copy(server, c)
		io.Copy(c, server)

	}
}

func authUser(user, pasd string) error {
	if value, ok := Users[user]; ok {
		if pasd == value {
			return nil
		} else {
			return errors.New(fmt.Sprintf("Wrong Password of %s", user))
		}
	}
	return errors.New(fmt.Sprintf("No such user: %s", user))
}
