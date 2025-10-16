package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/metacubex/mihomo/component/generater"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/updater"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/provider"

	"go.uber.org/automaxprocs/maxprocs"
)

var (
	version                bool
	testConfig             bool
	geodataMode            bool
	homeDir                string
	configFile             string
	configString           string
	configBytes            []byte
	xorConfigFile          string
	xorKey                 string
	externalUI             string
	externalController     string
	externalControllerUnix string
	externalControllerPipe string
	secret                 string
)

func init() {
	flag.StringVar(&homeDir, "d", os.Getenv("CLASH_HOME_DIR"), "set configuration directory")
	flag.StringVar(&configFile, "f", os.Getenv("CLASH_CONFIG_FILE"), "specify configuration file")
	flag.StringVar(&configString, "config", os.Getenv("CLASH_CONFIG_STRING"), "specify base64-encoded configuration string")
	flag.StringVar(&xorConfigFile, "xor-config", os.Getenv("CLASH_XOR_CONFIG_FILE"), "specify xor-encrypted configuration file")
	flag.StringVar(&xorKey, "xor-key", os.Getenv("CLASH_XOR_KEY"), "specify xor decryption key")
	flag.StringVar(&externalUI, "ext-ui", os.Getenv("CLASH_OVERRIDE_EXTERNAL_UI_DIR"), "override external ui directory")
	flag.StringVar(&externalController, "ext-ctl", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER"), "override external controller address")
	flag.StringVar(&externalControllerUnix, "ext-ctl-unix", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX"), "override external controller unix address")
	flag.StringVar(&externalControllerPipe, "ext-ctl-pipe", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_PIPE"), "override external controller pipe address")
	flag.StringVar(&secret, "secret", os.Getenv("CLASH_OVERRIDE_SECRET"), "override secret for RESTful API")
	flag.BoolVar(&geodataMode, "m", false, "set geodata mode")
	flag.BoolVar(&version, "v", false, "show current version of mihomo")
	flag.BoolVar(&testConfig, "t", false, "test configuration and exit")
	flag.Parse()
}

// xorDecrypt 解密异或加密的base64字符串
func xorDecrypt(encryptedData string, key string) ([]byte, error) {
	// 解码base64
	encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %v", err)
	}

	// 将密钥转换为字节数组
	keyBytes := []byte(key)
	if len(keyBytes) == 0 {
		return nil, fmt.Errorf("xor key cannot be empty")
	}

	// 异或解密
	decryptedBytes := make([]byte, len(encryptedBytes))
	for i := 0; i < len(encryptedBytes); i++ {
		decryptedBytes[i] = encryptedBytes[i] ^ keyBytes[i%len(keyBytes)]
	}

	return decryptedBytes, nil
}

func main() {
	// Defensive programming: panic when code mistakenly calls net.DefaultResolver
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		panic("should never be called")
	}

	_, _ = maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))

	if len(os.Args) > 1 && os.Args[1] == "convert-ruleset" {
		provider.ConvertMain(os.Args[2:])
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "generate" {
		generater.Main(os.Args[2:])
		return
	}

	if version {
		fmt.Printf("Mihomo Meta %s %s %s with %s %s\n",
			C.Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), C.BuildTime)
		if tags := features.Tags(); len(tags) != 0 {
			fmt.Printf("Use tags: %s\n", strings.Join(tags, ", "))
		}

		return
	}

	if homeDir != "" {
		if !filepath.IsAbs(homeDir) {
			currentDir, _ := os.Getwd()
			homeDir = filepath.Join(currentDir, homeDir)
		}
		C.SetHomeDir(homeDir)
	}

	if geodataMode {
		geodata.SetGeodataMode(true)
	}

	if configString != "" {
		var err error
		configBytes, err = base64.StdEncoding.DecodeString(configString)
		if err != nil {
			log.Fatalln("Initial configuration error: %s", err.Error())
			return
		}
	} else if xorConfigFile != "" {
		// 处理异或加密的配置文件
		if xorKey == "" {
			log.Fatalln("XOR key is required when using xor-config file")
			return
		}
		
		if !filepath.IsAbs(xorConfigFile) {
			currentDir, _ := os.Getwd()
			xorConfigFile = filepath.Join(currentDir, xorConfigFile)
		}
		
		// 读取加密的配置文件
		encryptedData, err := os.ReadFile(xorConfigFile)
		if err != nil {
			log.Fatalln("Failed to read xor config file: %s", err.Error())
			return
		}
		
		// 解密配置文件
		configBytes, err = xorDecrypt(string(encryptedData), xorKey)
		if err != nil {
			log.Fatalln("Failed to decrypt xor config file: %s", err.Error())
			return
		}
		
		C.SetConfig(xorConfigFile)
		
		if err := config.Init(C.Path.HomeDir()); err != nil {
			log.Fatalln("Initial configuration directory error: %s", err.Error())
		}
	} else if configFile == "-" {
		var err error
		configBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalln("Initial configuration error: %s", err.Error())
			return
		}
	} else {
		if configFile != "" {
			if !filepath.IsAbs(configFile) {
				currentDir, _ := os.Getwd()
				configFile = filepath.Join(currentDir, configFile)
			}
		} else {
			configFile = filepath.Join(C.Path.HomeDir(), C.Path.Config())
		}
		C.SetConfig(configFile)

		if err := config.Init(C.Path.HomeDir()); err != nil {
			log.Fatalln("Initial configuration directory error: %s", err.Error())
		}
	}

	if testConfig {
		if len(configBytes) != 0 {
			if _, err := executor.ParseWithBytes(configBytes); err != nil {
				log.Errorln(err.Error())
				fmt.Println("configuration test failed")
				os.Exit(1)
			}
		} else {
			if _, err := executor.Parse(); err != nil {
				log.Errorln(err.Error())
				fmt.Printf("configuration file %s test failed\n", C.Path.Config())
				os.Exit(1)
			}
		}
		fmt.Printf("configuration file %s test is successful\n", C.Path.Config())
		return
	}

	var options []hub.Option
	if externalUI != "" {
		options = append(options, hub.WithExternalUI(externalUI))
	}
	if externalController != "" {
		options = append(options, hub.WithExternalController(externalController))
	}
	if externalControllerUnix != "" {
		options = append(options, hub.WithExternalControllerUnix(externalControllerUnix))
	}
	if externalControllerPipe != "" {
		options = append(options, hub.WithExternalControllerPipe(externalControllerPipe))
	}
	if secret != "" {
		options = append(options, hub.WithSecret(secret))
	}

	if err := hub.Parse(configBytes, options...); err != nil {
		log.Fatalln("Parse config error: %s", err.Error())
	}

	if updater.GeoAutoUpdate() {
		updater.RegisterGeoUpdater()
	}

	defer executor.Shutdown()

	termSign := make(chan os.Signal, 1)
	hupSign := make(chan os.Signal, 1)
	signal.Notify(termSign, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(hupSign, syscall.SIGHUP)
	for {
		select {
		case <-termSign:
			return
		case <-hupSign:
			if err := hub.Parse(configBytes, options...); err != nil {
				log.Errorln("Parse config error: %s", err.Error())
			}
		}
	}
}
