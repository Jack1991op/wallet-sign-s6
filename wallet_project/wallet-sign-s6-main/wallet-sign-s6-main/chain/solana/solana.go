package solana

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/pkg/errors"
	"math"
	"strconv"

	"github.com/cosmos/btcutil/base58"
	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/log"

	"github.com/gagliardetto/solana-go"
	associatedtokenaccount "github.com/gagliardetto/solana-go/programs/associated-token-account"
	"github.com/gagliardetto/solana-go/programs/system"
	"github.com/gagliardetto/solana-go/programs/token"

	"github.com/dapplink-baas/wallet-sign-server/chain"
	"github.com/dapplink-baas/wallet-sign-server/config"
	"github.com/dapplink-baas/wallet-sign-server/hsm"
	"github.com/dapplink-baas/wallet-sign-server/leveldb"
	"github.com/dapplink-baas/wallet-sign-server/protobuf/wallet"
	"github.com/dapplink-baas/wallet-sign-server/ssm"
)

const ChainName = "Solana"

type ChainAdaptor struct {
	db        *leveldb.Keys
	HsmClient *hsm.HsmClient
	signer    ssm.Signer
}

func NewChainAdaptor(conf *config.Config, db *leveldb.Keys, hsmCli *hsm.HsmClient) (chain.IChainAdaptor, error) {
	return &ChainAdaptor{
		db:        db,
		signer:    &ssm.EdDSASigner{},
		HsmClient: hsmCli,
	}, nil
}

func (c ChainAdaptor) GetChainSignMethod(ctx context.Context, req *wallet.ChainSignMethodRequest) (*wallet.ChainSignMethodResponse, error) {
	return &wallet.ChainSignMethodResponse{
		Code:       wallet.ReturnCode_SUCCESS,
		Message:    "get sign method success",
		SignMethod: "eddsa",
	}, nil
}

func (c ChainAdaptor) GetChainSchema(ctx context.Context, req *wallet.ChainSchemaRequest) (*wallet.ChainSchemaResponse, error) {
	ss := SolanaSchema{
		Nonce:           "",
		GasPrice:        "",
		GasTipCap:       "",
		GasFeeCap:       "",
		Gas:             0,
		ContractAddress: "",
		FromAddress:     "",
		ToAddress:       "",
		TokenId:         "",
		Value:           "",
	}
	b, err := json.Marshal(ss)
	if err != nil {
		log.Error("marshal fail", "err", err)
	}
	return &wallet.ChainSchemaResponse{
		Code:    wallet.ReturnCode_SUCCESS,
		Message: "get solana sign schema success",
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
		priKeyStr, pubKeyStr, compressPubKeyStr, err := c.signer.CreateKeyPair()
		if err != nil {
			if req.KeyNum > 10000 {
				resp.Message = "create key pair fail"
				return resp, nil
			}
		}
		keyItem := leveldb.Key{
			PrivateKey: priKeyStr,
			Pubkey:     pubKeyStr,
		}
		pukItem := &wallet.ExportPublicKey{
			PublicKey:         pubKeyStr,
			CompressPublicKey: compressPubKeyStr,
		}
		retKeyList = append(retKeyList, pukItem)
		keyList = append(keyList, keyItem)
	}
	isOk := c.db.StoreKeys(keyList)
	if !isOk {
		resp.Message = "store keys fail"
		return resp, nil
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
	var retKeyList []*wallet.ExportPublicKeyWithAddress
	for counter := 0; counter < int(req.KeyNum); counter++ {
		priKeyStr, pubKeyStr, compressPubKeyStr, err := c.signer.CreateKeyPair()
		if err != nil {
			if req.KeyNum > 10000 {
				resp.Message = "create key pair fail"
				return resp, nil
			}
		}
		keyItem := leveldb.Key{
			PrivateKey: priKeyStr,
			Pubkey:     pubKeyStr,
		}

		address, err := PubKeyHexToAddress(pubKeyStr)
		if err != nil {
			resp.Message = "public key to address fail"
			return resp, nil
		}

		pukItem := &wallet.ExportPublicKeyWithAddress{
			PublicKey:         pubKeyStr,
			CompressPublicKey: compressPubKeyStr,
			Address:           address,
		}
		retKeyList = append(retKeyList, pukItem)
		keyList = append(keyList, keyItem)
	}
	isOk := c.db.StoreKeys(keyList)
	if !isOk {
		resp.Message = "store keys fail"
		return resp, nil
	}
	resp.Code = wallet.ReturnCode_SUCCESS
	resp.Message = "create keys success"
	resp.PublicKeyAddresses = retKeyList
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
	jsonBytes, err := base64.StdEncoding.DecodeString(req.TxBase64Body)
	if err != nil {
		resp.Message = "Failed to decode base64 string"
		return resp, nil
	}
	var data SolanaSchema
	if err := json.Unmarshal(jsonBytes, &data); err != nil {
		resp.Message = "Failed to parse json"
		return resp, nil
	}
	value, _ := strconv.ParseUint(data.Value, 10, 64)

	fromPubkey, err := solana.PublicKeyFromBase58(data.FromAddress)
	if err != nil {
		resp.Message = "Failed to parse public key from base58 by from address"
		return resp, nil
	}

	toPubkey, err := solana.PublicKeyFromBase58(data.ToAddress)
	if err != nil {
		resp.Message = "Failed to parse public key from base58 by to address"
		return resp, nil
	}
	var tx *solana.Transaction
	if isSOLTransfer(data.ContractAddress) {
		tx, err = solana.NewTransaction(
			[]solana.Instruction{
				system.NewTransferInstruction(
					value,
					fromPubkey,
					toPubkey,
				).Build(),
			},
			solana.MustHashFromBase58(data.Nonce),
			solana.TransactionPayer(fromPubkey),
		)
	} else {
		mintPubkey := solana.MustPublicKeyFromBase58(data.ContractAddress)
		fromTokenAccount, _, err := solana.FindAssociatedTokenAddress(
			fromPubkey,
			mintPubkey,
		)
		if err != nil {
			resp.Message = "failed to find associated token address"
			return resp, nil
		}
		toTokenAccount, _, err := solana.FindAssociatedTokenAddress(
			toPubkey,
			mintPubkey,
		)
		if err != nil {
			resp.Message = "failed to find associated token address"
			return resp, nil
		}

		decimals := data.Decimal

		valueFloat, err := strconv.ParseFloat(data.Value, 64)
		if err != nil {
			resp.Message = "failed to parse value"
			return resp, nil
		}
		actualValue := uint64(valueFloat * math.Pow10(int(decimals)))

		transferInstruction := token.NewTransferInstruction(
			actualValue,
			fromTokenAccount,
			toTokenAccount,
			fromPubkey,
			[]solana.PublicKey{},
		).Build()
		if err != nil || data.TokenCreate {
			createATAInstruction := associatedtokenaccount.NewCreateInstruction(
				fromPubkey,
				toPubkey,
				mintPubkey,
			).Build()
			tx, err = solana.NewTransaction(
				[]solana.Instruction{createATAInstruction, transferInstruction},
				solana.MustHashFromBase58(data.Nonce),
				solana.TransactionPayer(fromPubkey),
			)
		} else {
			tx, err = solana.NewTransaction(
				[]solana.Instruction{transferInstruction},
				solana.MustHashFromBase58(data.Nonce),
				solana.TransactionPayer(fromPubkey),
			)
		}
	}
	log.Info("Transaction:", tx.String())
	txm, _ := tx.Message.MarshalBinary()
	signingMessageHex := hex.EncodeToString(txm)

	log.Info("this is we should use sign message hash", "signingMessageHex", signingMessageHex)

	privKey, isOk := c.db.GetPrivKey(req.PublicKey)
	if !isOk {
		resp.Message = "get private key by public key fail"
		return resp, nil
	}
	txSignatures, err := c.signer.SignMessage(privKey, signingMessageHex)
	if err != nil {
		resp.Message = "sign message hash fail"
		return resp, nil
	}
	if len(txSignatures) == 0 {
		tx.Signatures = make([]solana.Signature, 1)
	}
	if len(txSignatures) != 64 {
		resp.Message = "Invalid wallet-sign-server length"
		return resp, nil
	}
	var solanaSig solana.Signature
	copy(solanaSig[:], txSignatures)
	tx.Signatures[0] = solanaSig
	spew.Dump(tx)
	if err := tx.VerifySignatures(); err != nil {
		resp.Message = "Invalid wallet-sign-server"
		return resp, nil
	}
	serializedTx, err := tx.MarshalBinary()
	if err != nil {
		resp.Message = "Failed to serialize transaction"
		return resp, nil
	}
	log.Info("serialized transaction", "serializedTx", serializedTx)
	base58Tx := base58.Encode(serializedTx)

	resp.Code = wallet.ReturnCode_SUCCESS
	resp.SignedTx = base58Tx
	return resp, nil
}

func (c ChainAdaptor) BuildAndSignBatchTransaction(ctx context.Context, req *wallet.BuildAndSignBatchTransactionRequest) (*wallet.BuildAndSignBatchTransactionResponse, error) {
	panic("implement me")
}

func isSOLTransfer(coinAddress string) bool {
	return coinAddress == "" ||
		coinAddress == "So11111111111111111111111111111111111111112"
}
