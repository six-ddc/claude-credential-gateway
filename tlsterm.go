// tlsterm.go 为隧道流量提供 TLS 终结。
//
// 为什么必须终结 TLS:客户端设了 ANTHROPIC_UNIX_SOCKET 后,只是把【传输层】换成 unix socket,
// 目标 URL 仍是 https://api.anthropic.com —— 它照常发起完整 TLS 握手(SNI=api.anthropic.com)。
// 网关要替换 Authorization 注入真凭证,就必须先解密,所以得拿一张客户端认可的
// api.anthropic.com 证书。做法:网关自建 CA(落盘长期复用,设备端 pin 它),
// 每次启动在内存里用它签一张叶证书;设备用 NODE_EXTRA_CA_CERTS 信任该 CA 即可。
//
// 这只解密【你自己设备发给你自己网关】的流量,等价于 claude ssh 本地代理做的事。
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

// forgedHost 是叶证书要冒充的主机名 —— socket 模式下客户端固定按它做 SNI/证书校验。
const forgedHost = "api.anthropic.com"

// certAuthority 是网关自建的 CA。私钥与证书存同一个文件(0600),
// 另导出仅含证书的 <path>.crt(0644)供设备端 NODE_EXTRA_CA_CERTS 使用。
type certAuthority struct {
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	certPath    string // 分发给设备的证书路径
	fingerprint string // SHA256(DER),设备端比对用
}

// loadOrCreateCA 加载 CA;文件不存在则生成一把并落盘(私钥 0600)。
func loadOrCreateCA(path string) (*certAuthority, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return createCA(path)
	}
	if err != nil {
		return nil, err
	}
	ca, err := parseCA(data, path)
	if err != nil {
		return nil, fmt.Errorf("解析 CA %s: %w", path, err)
	}
	// .crt 可能被误删,确保设备端随时能取到
	if err := os.WriteFile(ca.certPath, pemBlock("CERTIFICATE", ca.cert.Raw), 0o644); err != nil {
		return nil, err
	}
	return ca, nil
}

func parseCA(data []byte, path string) (*certAuthority, error) {
	ca := &certAuthority{certPath: path + ".crt"}
	for rest := data; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			ca.cert = cert
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			ca.key = key
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			ecKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("CA 私钥类型不支持: %T(需要 ECDSA)", key)
			}
			ca.key = ecKey
		}
	}
	if ca.cert == nil || ca.key == nil {
		return nil, errors.New("文件里缺少 CERTIFICATE 或 PRIVATE KEY 块")
	}
	ca.fingerprint = certFingerprint(ca.cert)
	return ca, nil
}

func createCA(path string) (*certAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "claude-credential-gateway CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(pemBlock("CERTIFICATE", der))
	buf.Write(pemBlock("PRIVATE KEY", keyDER))
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		return nil, err
	}
	ca := &certAuthority{cert: cert, key: key, certPath: path + ".crt", fingerprint: certFingerprint(cert)}
	if err := os.WriteFile(ca.certPath, pemBlock("CERTIFICATE", der), 0o644); err != nil {
		return nil, err
	}
	log.Printf("已生成 TLS 终结 CA: %s(设备端信任 %s)", path, ca.certPath)
	return ca, nil
}

// serverTLSConfig 用 CA 现签一张叶证书,组装成隧道用的服务端 TLS 配置。
// 叶证书只在内存里、每次启动重签 —— 设备信任的是 CA,不受叶证书更替影响。
func (ca *certAuthority) serverTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: forgedHost},
		// localhost/127.0.0.1 便于用 curl --resolve 之类的方式直接调试隧道
		DNSNames:              []string{forgedHost, "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		// 只报 http/1.1:网关这一侧是 HTTP/1.1 server,别让客户端谈成 h2。
		NextProtos: []string{"http/1.1"},
	}, nil
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
