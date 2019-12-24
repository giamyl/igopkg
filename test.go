package main

import (
	"encoding/base64"
	"fmt"
	"github.com/giamyl/igopkg/icrypto"
)

func main() {

	ic := icrypto.Iaes{
		Key:[]byte("12345678901234567890123456789012"),
		Iv:[]byte("0000000000000000"),
	}

	rs,_ := ic.Encrypt(`{"code":200201201,"data":"消息内容","msg":"成功"}`)
	base64string := base64.StdEncoding.EncodeToString(rs)
	fmt.Println(base64string)

	//base64string:="5zvUyzbVr0Z7bkT97NhfqgoKq6xUTidyY2yVtTLRUkoKUoRXepk5eVoe+2atDhFDFLitZpH1paMKGSj+wZMNrQ=="
	rsdata, _ := ic.Decrypt(base64string)
	fmt.Println(string(rsdata))


}
