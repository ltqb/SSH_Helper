package main

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"unsafe"
)

func main() {

	basetable := "IJjkKLMNO567PWQX12RV3YZaDEFGbcdefghiABCHlSTUmnopqrxyz04stuvw89+/"
	var password string
	fmt.Println("请输入一个字符串：")
	fmt.Scanln(&password)
	fmt.Println("字符串加密后：", Encode(password, basetable))

}

func Encode(data string, BASE64Table string) string {
	content := *(*[]byte)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&data))))
	coder := base64.NewEncoding(BASE64Table)
	return coder.EncodeToString(content)
}

func Decode(data string, BASE64Table string) string {
	coder := base64.NewEncoding(BASE64Table)
	result, _ := coder.DecodeString(data)
	return *(*string)(unsafe.Pointer(&result))
}
