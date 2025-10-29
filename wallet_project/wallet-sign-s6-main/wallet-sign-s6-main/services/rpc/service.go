package rpc

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/ethereum/go-ethereum/log"

	"github.com/dapplink-baas/wallet-sign-server/chaindispatcher"
	"github.com/dapplink-baas/wallet-sign-server/config"
	"github.com/dapplink-baas/wallet-sign-server/hsm"
	"github.com/dapplink-baas/wallet-sign-server/protobuf/wallet"
)

const MaxReceivedMessageSize = 1024 * 1024 * 30000

type RpcService struct {
	conf      *config.Config
	HsmClient *hsm.HsmClient
	wallet.UnimplementedWalletServiceServer
	stopped atomic.Bool
}

func (s *RpcService) Stop(ctx context.Context) error {
	s.stopped.Store(true)
	return nil
}

func (s *RpcService) Stopped() bool {
	return s.stopped.Load()
}

func NewRpcService(conf *config.Config) (*RpcService, error) {
	rpcService := &RpcService{
		conf: conf,
	}
	var hsmCli *hsm.HsmClient
	var hsmErr error
	if conf.HsmEnable {
		hsmCli, hsmErr = hsm.NewHSMClient(context.Background(), conf.KeyPath, conf.KeyName)
		if hsmErr != nil {
			log.Error("new hsm client fail", "hsmErr", hsmErr)
			return nil, hsmErr
		}
		rpcService.HsmClient = hsmCli
	}
	return rpcService, nil
}

func (s *RpcService) Start(ctx context.Context) error {
	go func(s *RpcService) {

		addr := fmt.Sprintf("%s:%d", s.conf.RpcServer.Host, s.conf.RpcServer.Port)

		opt := grpc.MaxRecvMsgSize(MaxReceivedMessageSize)

		dispatcher, err := chaindispatcher.NewChainDispatcher(s.conf)
		if err != nil {
			log.Error("new chain dispatcher fail", "err", err)
			return
		}

		gs := grpc.NewServer(opt, grpc.ChainUnaryInterceptor(dispatcher.Interceptor))
		defer gs.GracefulStop()

		wallet.RegisterWalletServiceServer(gs, dispatcher)

		listener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Error("Could not start tcp listener. ")
			return
		}
		reflection.Register(gs) // grpcui -plaintext 127.0.0.1:port

		log.Info("Grpc info", "port", s.conf.RpcServer.Port, "address", listener.Addr())

		if err := gs.Serve(listener); err != nil {
			log.Error("Could not GRPC services")
		}
	}(s)
	return nil
}
