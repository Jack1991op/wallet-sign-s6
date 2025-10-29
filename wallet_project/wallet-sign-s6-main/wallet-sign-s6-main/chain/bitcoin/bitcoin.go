package bitcoin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/ethereum/go-ethereum/log"
	"github.com/pkg/errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/dapplink-baas/wallet-sign-server/chain"
	"github.com/dapplink-baas/wallet-sign-server/config"
	"github.com/dapplink-baas/wallet-sign-server/hsm"
	"github.com/dapplink-baas/wallet-sign-server/leveldb"
	"github.com/dapplink-baas/wallet-sign-server/protobuf/wallet"
	"github.com/dapplink-baas/wallet-sign-server/ssm"
)

const ChainName = "Bitcoin"

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
	var vins []*Vin
	vins = append(vins, &Vin{
		Hash:   "",
		Index:  0,
		Amount: 0,
	})
	var vouts []*Vout
	vouts = append(vouts, &Vout{
		Address: "",
		Index:   0,
		Amount:  0,
	})
	bs := BitcoinSechma{
		RequestId: "0",
		Fee:       "0",
		Vins:      vins,
		Vouts:     vouts,
	}
	b, err := json.Marshal(bs)
	if err != nil {
		log.Error("marshal fail", "err", err)
	}
	return &wallet.ChainSchemaResponse{
		Code:    wallet.ReturnCode_SUCCESS,
		Message: "get bitcoin sign schema success",
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
		pukAddressItem := &wallet.ExportPublicKey{
			CompressPublicKey: compressPubkeyStr,
			PublicKey:         pubKeyStr,
		}
		retKeyList = append(retKeyList, pukAddressItem)
		keyList = append(keyList, keyItem)
	}
	isOk := c.db.StoreKeys(keyList)
	if !isOk {
		log.Error("store keys fail", "isOk", isOk)
		return nil, errors.New("store keys fail")
	}
	resp.Code = wallet.ReturnCode_SUCCESS
	resp.Message = "create keys with address success"
	resp.PublicKeyList = retKeyList
	return resp, nil
}

func (c ChainAdaptor) CreateKeyPairsWithAddresses(ctx context.Context, req *wallet.CreateKeyPairsWithAddressesRequest) (*wallet.CreateKeyPairsWithAddressesResponse, error) {
	resp := &wallet.CreateKeyPairsWithAddressesResponse{
		Code: wallet.ReturnCode_ERROR,
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

		var address string
		compressedPubKeyBytes, _ := hex.DecodeString(compressPubkeyStr)
		pubKeyHash := btcutil.Hash160(compressedPubKeyBytes)
		switch req.AddressFormat {
		case "p2pkh":
			p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
			if err != nil {
				resp.Message = "create p2pkh address fail"
				return resp, nil
			}
			address = p2pkhAddr.EncodeAddress()
			break
		case "p2wpkh":
			witnessAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
			if err != nil {
				resp.Message = "create p2wpkh fail"
				return resp, nil
			}
			address = witnessAddr.EncodeAddress()
			break
		case "p2sh":
			witnessAddr, _ := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
			script, err := txscript.PayToAddrScript(witnessAddr)
			if err != nil {
				resp.Message = "create p2sh address script fail"
				return resp, nil
			}
			p2shAddr, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
			if err != nil {
				resp.Message = "create p2sh address fail"
				return resp, nil
			}
			address = p2shAddr.EncodeAddress()
			break
		case "p2tr":
			pubKey, err := btcec.ParsePubKey(compressedPubKeyBytes)
			if err != nil {
				resp.Message = "parse public key fail"
				return resp, nil
			}
			taprootPubKey := schnorr.SerializePubKey(pubKey)
			taprootAddr, err := btcutil.NewAddressTaproot(taprootPubKey, &chaincfg.MainNetParams)
			if err != nil {
				resp.Message = "create taproot address fail"
				return resp, nil
			}
			address = taprootAddr.EncodeAddress()
		default:
			resp.Message = "Do not support address type"
			return resp, nil
		}
		pukAddressItem := &wallet.ExportPublicKeyWithAddress{
			CompressPublicKey: compressPubkeyStr,
			PublicKey:         pubKeyStr,
			Address:           address,
		}
		retKeyWithAddressList = append(retKeyWithAddressList, pukAddressItem)
		keyList = append(keyList, keyItem)
	}
	isOk := c.db.StoreKeys(keyList)
	if !isOk {
		resp.Message = "store keys fail"
		return resp, nil
	}
	resp.Message = "create key pairs with address success"
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

	txReqJsonByte, err := base64.StdEncoding.DecodeString(req.TxBase64Body)
	if err != nil {
		resp.Message = "decode string fail"
		return resp, nil
	}

	// 2. Unmarshal JSON to struct
	var bitcoinSechma BitcoinSechma
	if err := json.Unmarshal(txReqJsonByte, &bitcoinSechma); err != nil {
		resp.Message = "parse json fail"
		return resp, nil
	}

	txHash, buf, err := c.CalcSignHashes(bitcoinSechma.Vins, bitcoinSechma.Vouts)
	if err != nil {
		resp.Message = "calc sign hashes fail"
		return resp, nil
	}
	log.Info("calc sign hash success", "txHash", txHash, "buf", buf)

	privKey, isOk := c.db.GetPrivKey(req.PublicKey)
	if !isOk {
		resp.Message = "get private key by public key fail"
		return resp, nil
	}
	signture, err := c.signer.SignMessage(privKey, string(buf))
	if err != nil {
		resp.Message = "sign message fail"
		return resp, nil
	}

	//var msgTx wire.MsgTx
	//err = msgTx.Deserialize(nil)
	//if err != nil {
	//	log.Error("deserialized fail")
	//}

	//for i, in := range msgTx.TxIn {
	//	btcecPub, err2 := btcec.ParsePubKey([]byte(req.PublicKey))
	//	if err2 != nil {
	//
	//	}
	//	var pkData []byte
	//	if btcec.IsCompressedPubKey([]byte(req.PublicKey)) {
	//		pkData = btcecPub.SerializeCompressed()
	//	} else {
	//		pkData = btcecPub.SerializeUncompressed()
	//	}
	//
	//	var r *btcec.ModNScalar
	//	R := r.SetInt(r.SetBytes(signture))
	//	var s *btcec.ModNScalar
	//	S := s.SetInt(r.SetBytes(signture))
	//	btcecSig := ecdsa.NewSignature(R, S)
	//	sig := append(btcecSig.Serialize(), byte(txscript.SigHashAll))
	//	sigScript, err2 := txscript.NewScriptBuilder().AddData(sig).AddData(pkData).Script()
	//	if err2 != nil {
	//
	//	}
	//	msgTx.TxIn[i].SignatureScript = sigScript
	//
	//	vm, err2 := txscript.NewEngine(nil, &msgTx, i, txscript.StandardVerifyFlags, nil, nil, amount, nil)
	//	if err2 != nil {
	//
	//	}
	//	if err3 := vm.Execute(); err3 != nil {
	//		log.Error("CreateSignedTransaction NewEngine Execute", "err", err3)
	//	}
	//}
	//// serialize tx
	//buf := bytes.NewBuffer(make([]byte, 0, msgTx.SerializeSize()))
	//err = msgTx.Serialize(buf)
	//if err != nil {
	//
	//}
	// hash := msgTx.TxHash()
	resp.Code = wallet.ReturnCode_SUCCESS
	resp.Message = "sign tx success"
	resp.TxMessageHash = signture
	resp.TxHash = ""
	resp.SignedTx = ""
	return resp, nil
}

func (c ChainAdaptor) BuildAndSignBatchTransaction(ctx context.Context, req *wallet.BuildAndSignBatchTransactionRequest) (*wallet.BuildAndSignBatchTransactionResponse, error) {
	panic("implement me")
}

func (c *ChainAdaptor) CalcSignHashes(Vins []*Vin, Vouts []*Vout) ([][]byte, []byte, error) {
	if len(Vins) == 0 || len(Vouts) == 0 {
		return nil, nil, errors.New("invalid len in or out")
	}
	rawTx := wire.NewMsgTx(wire.TxVersion)
	for _, in := range Vins {
		utxoHash, err := chainhash.NewHashFromStr(in.Hash)
		if err != nil {
			return nil, nil, err
		}
		txIn := wire.NewTxIn(wire.NewOutPoint(utxoHash, uint32(in.Index)), nil, nil)
		rawTx.AddTxIn(txIn)
	}
	for _, out := range Vouts {
		toAddress, err := btcutil.DecodeAddress(out.Address, &chaincfg.MainNetParams)
		if err != nil {
			return nil, nil, err
		}
		toPkScript, err := txscript.PayToAddrScript(toAddress)
		if err != nil {
			return nil, nil, err
		}
		rawTx.AddTxOut(wire.NewTxOut(int64(out.Amount), toPkScript))
	}
	signHashes := make([][]byte, len(Vins))

	for i, in := range Vins {
		from := in.Address
		fromAddr, err := btcutil.DecodeAddress(from, &chaincfg.MainNetParams)
		if err != nil {
			log.Info("decode address error", "from", from, "err", err)
			return nil, nil, err
		}
		fromPkScript, err := txscript.PayToAddrScript(fromAddr)
		if err != nil {
			log.Info("pay to addr script err", "err", err)
			return nil, nil, err
		}
		signHash, err := txscript.CalcSignatureHash(fromPkScript, txscript.SigHashAll, rawTx, i)
		if err != nil {
			log.Info("Calc wallet-sign-server hash error", "err", err)
			return nil, nil, err
		}
		signHashes[i] = signHash
	}
	buf := bytes.NewBuffer(make([]byte, 0, rawTx.SerializeSize()))
	return signHashes, buf.Bytes(), nil
}
