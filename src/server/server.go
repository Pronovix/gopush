package main

import "gopush"

func main() {
	gopush.NewService("config.json", false).Start(":8080")
}
