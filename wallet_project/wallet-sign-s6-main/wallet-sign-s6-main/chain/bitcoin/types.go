package bitcoin

type Vin struct {
	Address string `json:"address"`
	Hash    string `json:"hash"`
	Index   uint64 `json:"index"`
	Amount  uint64 `json:"amount"`
}

type Vout struct {
	Address string `json:"address"`
	Amount  uint64 `json:"amount"`
	Index   uint64 `json:"index"`
}

type BitcoinSechma struct {
	RequestId string  `json:"request_id"`
	Fee       string  `json:"fee"`
	Vins      []*Vin  `json:"vins"`
	Vouts     []*Vout `json:"vouts"`
}
