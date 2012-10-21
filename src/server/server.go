package main

import "gopush"

func main() {
	gopush.NewService("config.json").Start(":8080")
}
