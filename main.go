package main

import (
	"fmt"
)

func main() {
	address := "localhost"
	server := NvServer{Address: address, BaseURL: "http://" + address + ":47989"}
	err := server.GetInfo()
	if err != nil {
		fmt.Println(err)
		return
	}

	//fmt.Printf("%+v\n", server)

	err = server.Pair("1234")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(server.ServerCert)

	err = server.GetAppList()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(server)
	server.Cleanup()
}
