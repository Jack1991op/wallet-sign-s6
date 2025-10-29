package ethereum

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/pkg/errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"

	"github.com/dapplink-baas/wallet-sign-server/chain"
	"github.com/dapplink-baas/wallet-sign-server/config"
	"github.com/dapplink-baas/wallet-sign-server/hsm"
	"github.com/dapplink-baas/wallet-sign-server/leveldb"
	"github.com/dapplink-baas/wallet-sign-server/protobuf/wallet"
	"github.com/dapplink-baas/wallet-sign-server/ssm"
)

const ChainName = "Ethereum"

type ChainAdaptor struct {
	db        *leveldb.Keys
	HsmClient *hsm.HsmClient
	signer    ssm.Signer
}

func NewChainAdaptor(conf *config.Config, db *leveldb.Keys, hsmCli *hsm.HsmClient) (chain.IChainAdaptor, error) {
	return &ChainAdaptor{
		db:        db,
		HsmClient: hsmCli,
		signer:    &ssm.ECDSASigner{},
	}, nil
}

func (c ChainAdaptor) GetChainSignMethod(ctx context.Context, req *wallet.ChainSignMethodRequest) (*wallet.ChainSignMethodResponse, error) {
	return &wallet.ChainSignMethodResponse{
		Code:       wallet.ReturnCode_SUCCESS,
		Message:    "get sign method success",
		SignMethod: "ecdsa",
	}, nil
}

func (c ChainAdaptor) GetChainSchema(ctx context.Context, req *wallet.ChainSchemaRequest) (*wallet.ChainSchemaResponse, error) {
	es := EthereumSchema{
		RequestId: "0",
		DynamicFeeTx: Eip1559DynamicFeeTx{
			ChainId:              "",
			Nonce:                0,
			FromAddress:          common.Address{}.String(),
			ToAddress:            common.Address{}.String(),
			GasLimit:             0,
			Gas:                  0,
			MaxFeePerGas:         "0",
			MaxPriorityFeePerGas: "0",
			Amount:               "0",
			ContractAddress:      "",
		},
		ClassicFeeTx: LegacyFeeTx{
			ChainId:         "0",
			Nonce:           0,
			FromAddress:     common.Address{}.String(),
			ToAddress:       common.Address{}.String(),
			GasLimit:        0,
			GasPrice:        0,
			Amount:          "0",
			ContractAddress: "",
		},
	}
	b, err := json.Marshal(es)
	if err != nil {
		log.Error("marshal fail", "err", err)
	}
	return &wallet.ChainSchemaResponse{
		Code:    wallet.ReturnCode_SUCCESS,
		Message: "get ethereum sign schema success",
		Schema:  string(b),
	}, nil
}

func (c ChainAdaptor) CreateKeyPairsExportPublicKeyList(ctx context.Context, req *wallet.CreateKeyPairAndExportPublicKeyRequest) (*wallet.CreateKeyPairAndExportPublicKeyResponse, error) {
	resp := &wallet.CreateKeyPairAndExportPublicKeyResponse{
		Code: wallet.ReturnCode_ERROR,
	}
	if req.KeyNum > 10000 {
		resp.Message = "Number must be less than 100000"
		return resp, nil
	}

	var keyList []leveldb.Key
	var retKeyList []*wallet.ExportPublicKey

	for counter := 0; counter < int(req.KeyNum); counter++ {
		priKeyStr, pubKeyStr, compressPubkeyStr, err := c.signer.CreateKeyPair()
		if err != nil {
			resp.Message = "create key pairs fail"
			return resp, nil
		}
		keyItem := leveldb.Key{
			PrivateKey: priKeyStr,
			Pubkey:     pubKeyStr,
		}
		pukItem := &wallet.ExportPublicKey{
			CompressPublicKey: compressPubkeyStr,
			PublicKey:         pubKeyStr,
		}
		retKeyList = append(retKeyList, pukItem)
		keyList = append(keyList, keyItem)
	}
	isOk := c.db.StoreKeys(keyList)
	if !isOk {
		log.Error("store keys fail", "isOk", isOk)
		return nil, errors.New("store keys fail")
	}
	resp.Code = wallet.ReturnCode_SUCCESS
	resp.Message = "create keys success"
	resp.PublicKeyList = retKeyList
	return resp, nil
}

func (c ChainAdaptor) CreateKeyPairsWithAddresses(ctx context.Context, req *wallet.CreateKeyPairsWithAddressesRequest) (*wallet.CreateKeyPairsWithAddressesResponse, error) {
	resp := &wallet.CreateKeyPairsWithAddressesResponse{
		Code: wallet.ReturnCode_ERROR,
	}
	if req.KeyNum > 10000 {
		resp.Message = "Number must be less than 100000"
		return resp, nil
	}
	var keyList []leveldb.Key
	var retKeyWithAddressList []*wallet.ExportPublicKeyWithAddress
	for counter := 0; counter < int(req.KeyNum); counter++ {
		priKeyStr, pubKeyStr, compressPubkeyStr, err := c.signer.CreateKeyPair()
		if err != nil {
			resp.Message = "create key pairs fail"
			return resp, nil
		}
		keyItem := leveldb.Key{
			PrivateKey: priKeyStr,
			Pubkey:     pubKeyStr,
		}
		publicKeyBytes, err := hex.DecodeString(pubKeyStr)
		pukAddressItem := &wallet.ExportPublicKeyWithAddress{
			CompressPublicKey: compressPubkeyStr,
			PublicKey:         pubKeyStr,
			Address:           common.BytesToAddress(crypto.Keccak256(publicKeyBytes[1:])[12:]).String(),
		}
		retKeyWithAddressList = append(retKeyWithAddressList, pukAddressItem)
		keyList = append(keyList, keyItem)
	}
	isOk := c.db.StoreKeys(keyList)
	if !isOk {
		log.Error("store keys fail", "isOk", isOk)
		return nil, errors.New("store keys fail")
	}
	resp.Code = wallet.ReturnCode_SUCCESS
	resp.Message = "create keys with address success"
	resp.PublicKeyAddresses = retKeyWithAddressList
	return resp, nil
}

func (c ChainAdaptor) SignTransactionMessage(ctx context.Context, req *wallet.SignTransactionMessageRequest) (*wallet.SignTransactionMessageResponse, error) {
	resp := &wallet.SignTransactionMessageResponse{
		Code: wallet.ReturnCode_ERROR,
	}

	privKey, isOk := c.db.GetPrivKey(req.PublicKey)
	if !isOk {
		return nil, errors.New("get private key by public key fail")
	}

	log.Info("private key is", "privateKey", privKey)

	signature, err := c.signer.SignMessage(privKey, req.MessageHash)
	if err != nil {
		log.Error("sign message fail", "err", err)
		return nil, err
	}
	resp.Message = "sign tx message success"
	resp.Signature = signature
	resp.Code = wallet.ReturnCode_SUCCESS
	return resp, nil
}

func (c ChainAdaptor) BuildAndSignTransaction(ctx context.Context, req *wallet.BuildAndSignTransactionRequest) (*wallet.BuildAndSignTransactionResponse, error) {
	resp := &wallet.BuildAndSignTransactionResponse{
		Code: wallet.ReturnCode_ERROR,
	}

	dFeeTx, _, err := c.buildDynamicFeeTx(req.TxBase64Body)
	if err != nil {
		return nil, err
	}

	rawTx, err := CreateEip1559UnSignTx(dFeeTx, dFeeTx.ChainID)
	if err != nil {
		log.Error("create un sign tx fail", "err", err)
		resp.Message = "get un sign tx fail"
		return resp, nil
	}

	privKey, isOk := c.db.GetPrivKey(req.PublicKey)
	if !isOk {
		log.Error("get private key by public key fail", "err", err)
		resp.Message = "get private key by public key fail"
		return resp, nil
	}

	signature, err := c.signer.SignMessage(privKey, rawTx)
	if err != nil {
		log.Error("sign transaction fail", "err", err)
		resp.Message = "sign transaction fail"
		return resp, nil
	}

	inputSignatureByteList, err := hex.DecodeString(signature)
	if err != nil {
		log.Error("decode wallet-sign-server failed", "err", err)
		resp.Message = "decode wallet-sign-server failed"
		return resp, nil
	}

	eip1559Signer, signedTx, signAndHandledTx, txHash, err := CreateEip1559SignedTx(dFeeTx, inputSignatureByteList, dFeeTx.ChainID)
	if err != nil {
		log.Error("create signed tx fail", "err", err)
		resp.Message = "create signed tx fail"
		return resp, nil
	}
	log.Info("sign transaction success",
		"eip1559Signer", eip1559Signer,
		"signedTx", signedTx,
		"signAndHandledTx", signAndHandledTx,
		"txHash", txHash,
	)
	resp.Code = wallet.ReturnCode_SUCCESS
	resp.Message = "sign whole transaction success"
	resp.SignedTx = signAndHandledTx
	resp.TxHash = txHash
	resp.TxMessageHash = rawTx
	return resp, nil
}

func (c ChainAdaptor) BuildAndSignBatchTransaction(ctx context.Context, req *wallet.BuildAndSignBatchTransactionRequest) (*wallet.BuildAndSignBatchTransactionResponse, error) {
	panic("implement me")
}

func (c ChainAdaptor) buildDynamicFeeTx(base64Tx string) (*types.DynamicFeeTx, *Eip1559DynamicFeeTx, error) {
	// 1. Decode base64 string
	txReqJsonByte, err := base64.StdEncoding.DecodeString(base64Tx)
	if err != nil {
		log.Error("decode string fail", "err", err)
		return nil, nil, err
	}

	// 2. Unmarshal JSON to struct
	var dynamicFeeTx Eip1559DynamicFeeTx
	if err := json.Unmarshal(txReqJsonByte, &dynamicFeeTx); err != nil {
		log.Error("parse json fail", "err", err)
		return nil, nil, err
	}

	// 3. Convert string values to big.Int
	chainID := new(big.Int)
	maxPriorityFeePerGas := new(big.Int)
	maxFeePerGas := new(big.Int)
	amount := new(big.Int)

	log.Info("Dynamic fee tx",
		"ChainId", dynamicFeeTx.ChainId,
		"MaxPriorityFeePerGas", dynamicFeeTx.MaxPriorityFeePerGas,
		"MaxFeePerGas", dynamicFeeTx.MaxFeePerGas,
		"Amount", dynamicFeeTx.Amount,
	)

	if _, ok := chainID.SetString(dynamicFeeTx.ChainId, 10); !ok {
		return nil, nil, fmt.Errorf("invalid chain ID: %s", dynamicFeeTx.ChainId)
	}
	if _, ok := maxPriorityFeePerGas.SetString(dynamicFeeTx.MaxPriorityFeePerGas, 10); !ok {
		return nil, nil, fmt.Errorf("invalid max priority fee: %s", dynamicFeeTx.MaxPriorityFeePerGas)
	}
	if _, ok := maxFeePerGas.SetString(dynamicFeeTx.MaxFeePerGas, 10); !ok {
		return nil, nil, fmt.Errorf("invalid max fee: %s", dynamicFeeTx.MaxFeePerGas)
	}
	if _, ok := amount.SetString(dynamicFeeTx.Amount, 10); !ok {
		return nil, nil, fmt.Errorf("invalid amount: %s", dynamicFeeTx.Amount)
	}

	// 4. Handle addresses and data
	toAddress := common.HexToAddress(dynamicFeeTx.ToAddress)
	var finalToAddress common.Address
	var finalAmount *big.Int
	var buildData []byte
	log.Info("contract address check",
		"contractAddress", dynamicFeeTx.ContractAddress,
		"isEthTransfer", isEthTransfer(&dynamicFeeTx),
	)

	// 5. Handle contract interaction vs direct transfer
	if isEthTransfer(&dynamicFeeTx) {
		log.Info("native token transfer")
		finalToAddress = toAddress
		finalAmount = amount
	} else {
		log.Info("erc20 token transfer")
		contractAddress := common.HexToAddress(dynamicFeeTx.ContractAddress)
		buildData = BuildErc20Data(toAddress, amount)
		finalToAddress = contractAddress
		finalAmount = big.NewInt(0)
	}

	// 6. Create dynamic fee transaction
	dFeeTx := &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     dynamicFeeTx.Nonce,
		GasTipCap: maxPriorityFeePerGas,
		GasFeeCap: maxFeePerGas,
		Gas:       dynamicFeeTx.GasLimit,
		To:        &finalToAddress,
		Value:     finalAmount,
		Data:      buildData,
	}

	return dFeeTx, &dynamicFeeTx, nil

}

func isEthTransfer(tx *Eip1559DynamicFeeTx) bool {
	if tx.ContractAddress == "" || strings.ToLower(tx.ContractAddress) == "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
		return true
	}
	return false
}
