package gethutil

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/params"
)

// Copied from github.com/ethereum/go-ethereum/internal/ethapi.ExecutionResult
// ExecutionResult groups all structured logs emitted by the EVM
// while replaying a transaction in debug mode as well as transaction
// execution status, the amount of gas used and the return value
type ExecutionResult struct {
	Gas         uint64         `json:"gas"`
	Failed      bool           `json:"failed"`
	ReturnValue string         `json:"returnValue"`
	StructLogs  []StructLogRes `json:"structLogs"`
}

// StructLogRes stores a structured log emitted by the EVM while replaying a
// transaction in debug mode
// Copied from github.com/ethereum/go-ethereum/internal/ethapi.StructLogRes
type StructLogRes struct {
	Pc      uint64             `json:"pc"`
	Op      string             `json:"op"`
	Gas     uint64             `json:"gas"`
	GasCost uint64             `json:"gasCost"`
	Depth   int                `json:"depth"`
	Error   string             `json:"error,omitempty"`
	Stack   *[]string          `json:"stack,omitempty"`
	Memory  *[]string          `json:"memory,omitempty"`
	Storage *map[string]string `json:"storage,omitempty"`
}

// Copied from github.com/ethereum/go-ethereum/internal/ethapi.FormatLogs
// FormatLogs formats EVM returned structured logs for json output
func FormatLogs(logs []logger.StructLog) []StructLogRes {
	formatted := make([]StructLogRes, len(logs))
	for index, trace := range logs {
		formatted[index] = StructLogRes{
			Pc:      trace.Pc,
			Op:      trace.Op.String(),
			Gas:     trace.Gas,
			GasCost: trace.GasCost,
			Depth:   trace.Depth,
			Error:   trace.ErrorString(),
		}
		if trace.Stack != nil {
			stack := make([]string, len(trace.Stack))
			for i, stackValue := range trace.Stack {
				stack[i] = stackValue.Hex()
			}
			formatted[index].Stack = &stack
		}
		if trace.Memory != nil {
			memory := make([]string, 0, (len(trace.Memory)+31)/32)
			for i := 0; i+32 <= len(trace.Memory); i += 32 {
				memory = append(memory, fmt.Sprintf("%x", trace.Memory[i:i+32]))
			}
			formatted[index].Memory = &memory
		}
		if trace.Storage != nil {
			storage := make(map[string]string)
			for i, storageValue := range trace.Storage {
				storage[fmt.Sprintf("%x", i)] = fmt.Sprintf("%x", storageValue)
			}
			formatted[index].Storage = &storage
		}
	}
	return formatted
}

type Block struct {
	ChainID       *hexutil.Big   `json:"chain_id"`
	Coinbase      common.Address `json:"coinbase"`
	Timestamp     *hexutil.Big   `json:"timestamp"`
	Number        *hexutil.Big   `json:"number"`
	Difficulty    *hexutil.Big   `json:"difficulty"`
	GasLimit      *hexutil.Big   `json:"gas_limit"`
	BaseFee       *hexutil.Big   `json:"base_fee"`
	HistoryHashes []*hexutil.Big `json:"history_hashes"`
}

type Account struct {
	Nonce   hexutil.Uint64              `json:"nonce"`
	Balance *hexutil.Big                `json:"balance"`
	Code    hexutil.Bytes               `json:"code"`
	Storage map[common.Hash]common.Hash `json:"storage"`
}

type Transaction struct {
	From       common.Address  `json:"from"`
	To         *common.Address `json:"to"`
	Nonce      hexutil.Uint64  `json:"nonce"`
	Value      *hexutil.Big    `json:"value"`
	GasLimit   hexutil.Uint64  `json:"gas_limit"`
	GasPrice   *hexutil.Big    `json:"gas_price"`
	GasFeeCap  *hexutil.Big    `json:"gas_fee_cap"`
	GasTipCap  *hexutil.Big    `json:"gas_tip_cap"`
	CallData   hexutil.Bytes   `json:"call_data"`
	AccessList []struct {
		Address     common.Address `json:"address"`
		StorageKeys []common.Hash  `json:"storage_keys"`
	} `json:"access_list"`
}

func TraceTx(block Block, accounts map[common.Address]Account, tx Transaction) (*ExecutionResult, error) {
	chainConfig := params.ChainConfig{
		ChainID:             toBigInt(block.ChainID),
		HomesteadBlock:      big.NewInt(0),
		DAOForkBlock:        big.NewInt(0),
		DAOForkSupport:      true,
		EIP150Block:         big.NewInt(0),
		EIP150Hash:          common.Hash{},
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
	}

	// If gas price is specified directly, the tx is treated as legacy one
	if tx.GasPrice != nil {
		block.BaseFee = new(hexutil.Big)
		tx.GasFeeCap = tx.GasPrice
		tx.GasTipCap = tx.GasPrice
	}

	blockCtx := vm.BlockContext{
		CanTransfer: core.CanTransfer,
		Transfer:    core.Transfer,
		GetHash: func(n uint64) common.Hash {
			number := block.Number.ToInt().Uint64()
			if number > n && number-n <= 256 {
				return common.BigToHash(toBigInt(block.HistoryHashes[256-number+n]))
			}
			return common.Hash{}
		},
		Coinbase:    block.Coinbase,
		BlockNumber: toBigInt(block.Number),
		Time:        toBigInt(block.Timestamp),
		Difficulty:  toBigInt(block.Difficulty),
		BaseFee:     toBigInt(block.BaseFee),
		GasLimit:    toBigInt(block.GasLimit).Uint64(),
	}

	txAccessList := make(types.AccessList, len(tx.AccessList))
	for i, accessList := range tx.AccessList {
		txAccessList[i].Address = accessList.Address
		txAccessList[i].StorageKeys = accessList.StorageKeys
	}
	message := types.NewMessage(
		tx.From,
		tx.To,
		uint64(tx.Nonce),
		toBigInt(tx.Value),
		uint64(tx.GasLimit),
		toBigInt(tx.GasPrice),
		toBigInt(tx.GasFeeCap),
		toBigInt(tx.GasTipCap),
		tx.CallData,
		txAccessList,
		false,
	)
	txContext := core.NewEVMTxContext(message)

	// Setup state db with accounts from argument
	stateDB, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	for address, account := range accounts {
		stateDB.SetNonce(address, uint64(account.Nonce))
		stateDB.SetCode(address, account.Code)
		if account.Balance != nil {
			stateDB.SetBalance(address, toBigInt(account.Balance))
		}
		for key, value := range account.Storage {
			stateDB.SetState(address, key, value)
		}
	}
	stateDB.Finalise(chainConfig.IsByzantium(blockCtx.BlockNumber))

	// Run the transaction with tracing enabled.
	tracer := logger.NewStructLogger(&logger.Config{EnableMemory: true})
	evm := vm.NewEVM(blockCtx, txContext, stateDB, &chainConfig, vm.Config{Debug: true, Tracer: tracer, NoBaseFee: true})
	result, err := core.ApplyMessage(evm, message, new(core.GasPool).AddGas(message.Gas()))
	if err != nil {
		return nil, err
	}

	return &ExecutionResult{
		Gas:         result.UsedGas,
		Failed:      result.Failed(),
		ReturnValue: fmt.Sprintf("%x", result.ReturnData),
		StructLogs:  FormatLogs(tracer.StructLogs()),
	}, nil
}
