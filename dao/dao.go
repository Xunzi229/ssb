package dao

import "fmt"

// 在 Run 之前创建，避免 ScreenInput 打在 nil channel 上。
var (
	TipChan  = make(chan string)
	StopChan = make(chan bool)
	MsgChan  = make(chan string)
)

func Run() {
	for {
		v := ""
		select {
		case tips := <-TipChan:
			fmt.Print(tips)
			_, _ = fmt.Scanln(&v)
			MsgChan <- v
		case <-StopChan:
			return
		}
	}
}

func ScreenInput(tip string) string {
	TipChan <- tip
	return <-MsgChan
}
