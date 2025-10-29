package ethereum

type Eip1559DynamicFeeTx struct {
	ChainId              string `json:"chain_id"`
	Nonce                uint64 `json:"nonce"`
	FromAddress          string `json:"from_address"`
	ToAddress            string `json:"to_address"`
	GasLimit             uint64 `json:"gas_limit"`
	Gas                  uint64 `json:"Gas"`
	MaxFeePerGas         string `json:"max_fee_per_gas"`
	MaxPriorityFeePerGas string `json:"max_priority_fee_per_gas"`
	Amount               string `json:"amount"`
	ContractAddress      string `json:"contract_address"`
}

type LegacyFeeTx struct {
	ChainId         string `json:"chain_id"`
	Nonce           uint64 `json:"nonce"`
	FromAddress     string `json:"from_address"`
	ToAddress       string `json:"to_address"`
	GasLimit        uint64 `json:"gas_limit"`
	GasPrice        uint64 `json:"gas_price"`
	Amount          string `json:"amount"`
	ContractAddress string `json:"contract_address"`
}

type EthereumSchema struct {
	RequestId    string              `json:"request_id"`
	DynamicFeeTx Eip1559DynamicFeeTx `json:"dynamic_fee_tx"`
	ClassicFeeTx LegacyFeeTx         `json:"classic_fee_tx"`
}
