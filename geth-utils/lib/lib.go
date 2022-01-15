package main

/*
   #include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"main/gethutil"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
)

type Config struct {
	Block       gethutil.Block                      `json:"block_constants"`
	Accounts    map[common.Address]gethutil.Account `json:"accounts"`
	Transaction gethutil.Transaction                `json:"transaction"`
}

// TODO: Add proper error handling.  For example, return an int, where 0 means
// ok, and !=0 means error.
//export CreateTrace
func CreateTrace(configStr *C.char) *C.char {
	var config Config
	err := json.Unmarshal([]byte(C.GoString(configStr)), &config)
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to unmarshal config, err: %v", err))
	}

	executionResult, err := gethutil.TraceTx(config.Block, config.Accounts, config.Transaction)
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to trace tx, err: %v", err))
	}

	bytes, err := json.MarshalIndent(executionResult, "", "  ")
	if err != nil {
		return C.CString(fmt.Sprintf("Failed to marshal ExecutionResult, err: %v", err))
	}

	return C.CString(string(bytes))
}

//export FreeString
func FreeString(str *C.char) {
	C.free(unsafe.Pointer(str))
}

func main() {}
