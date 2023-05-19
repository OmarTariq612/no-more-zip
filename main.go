package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

//go:embed index.html
var indexHTML embed.FS

const (
	certType          = "CERTIFICATE"
	rsaPrivateKeyType = "RSA PRIVATE KEY"
)

var (
	caCertPath   = fmt.Sprintf("ca%cca.crt", os.PathSeparator)
	caKeyPath    = fmt.Sprintf("ca%cca.key", os.PathSeparator)
	nextIDPath   = fmt.Sprintf("ca%cnextid.bin", os.PathSeparator)
	siteCertPath = fmt.Sprintf("storage%c%%s%csite.crt", os.PathSeparator, os.PathSeparator)
	siteKeyPath  = fmt.Sprintf("storage%c%%s%csite.key", os.PathSeparator, os.PathSeparator)
)

func GetCA() (caCert *x509.Certificate, caKey *rsa.PrivateKey, nextID uint64, err error) {
	log.Println("=== getting the current ca ===")
	caCert, caKey, nextID, err = GetCurrentCA()
	if err != nil {
		log.Println("=== error happened while getting the current ca ===")
		log.Println("=== generating a new ca ===")
		caCert, caKey, nextID, err = GenerateNewCA()
	}

	return
}

func GetCurrentCA() (caCert *x509.Certificate, caKey *rsa.PrivateKey, nextID uint64, err error) {
	caCertRaw, err := os.ReadFile(caCertPath)
	if err != nil {
		return
	}

	block, _ := pem.Decode(caCertRaw)
	caCert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return
	}

	caKeyRaw, err := os.ReadFile(caKeyPath)
	if err != nil {
		return
	}
	block, _ = pem.Decode(caKeyRaw)
	caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}

	var nextIDBytes []byte
	nextIDBytes, err = os.ReadFile(nextIDPath)
	if err != nil {
		return
	}
	nextID = binary.LittleEndian.Uint64(nextIDBytes)

	return
}

func GenerateNewCA() (caCert *x509.Certificate, caKey *rsa.PrivateKey, nextID uint64, err error) {
	caCert = &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Omar's Organisation"},
			Country:      []string{"EG"},
			Locality:     []string{"Minia"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caKey, err = rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}

	caCertBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caKey.PublicKey, caKey)
	if err != nil {
		return
	}

	if _, err = os.Stat("ca"); errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir("ca", 0o755); err != nil {
			return
		}
	}

	if err = os.RemoveAll("storage"); err != nil {
		return
	}

	buffer := new(bytes.Buffer)
	err = pem.Encode(buffer, &pem.Block{
		Type:  certType,
		Bytes: caCertBytes,
	})
	if err != nil {
		return
	}
	if err = os.WriteFile(caCertPath, buffer.Bytes(), 0o644); err != nil {
		return
	}
	buffer.Reset()

	pem.Encode(buffer, &pem.Block{
		Type:  rsaPrivateKeyType,
		Bytes: x509.MarshalPKCS1PrivateKey(caKey),
	})
	if err != nil {
		return
	}
	if err = os.WriteFile(caKeyPath, buffer.Bytes(), 0o644); err != nil {
		return
	}

	nextID = 2
	bytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(bytes, nextID)
	if err = os.WriteFile(nextIDPath, bytes, 0o644); err != nil {
		return
	}

	return
}

func GetSiteTLSCertificate(sni string, caCert *x509.Certificate, caKey *rsa.PrivateKey, nextID *uint64) (*tls.Certificate, error) {
	sniSha1SumBytes := sha1.Sum([]byte(sni))
	sniSha1SumStr := hex.EncodeToString(sniSha1SumBytes[:])

	if _, err := os.Stat("storage"); errors.Is(err, os.ErrNotExist) {
		if err = os.Mkdir("storage", 0o755); err != nil {
			return nil, err
		}
	}

	_, dirErr := os.Stat(fmt.Sprintf("storage%c%s", os.PathSeparator, sniSha1SumStr))

	if errors.Is(dirErr, os.ErrNotExist) {
		if err := os.Mkdir(fmt.Sprintf("storage%c%s", os.PathSeparator, sniSha1SumStr), 0o755); err != nil {
			return nil, err
		}
	}

	_, siteKeyErr := os.Stat(fmt.Sprintf(siteKeyPath, sniSha1SumStr))
	_, siteCertErr := os.Stat(fmt.Sprintf(siteCertPath, sniSha1SumStr))
	var certPEM, certPrivKeyPEM []byte

	if errors.Is(siteKeyErr, os.ErrNotExist) || errors.Is(siteCertErr, os.ErrNotExist) {
		cert := &x509.Certificate{
			SerialNumber: big.NewInt(int64(*nextID)),
			Subject: pkix.Name{
				Organization: []string{"Omar's Organisation"},
				Country:      []string{"EG"},
				Locality:     []string{"Minia"},
			},
			DNSNames:     []string{sni},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().AddDate(10, 0, 0),
			SubjectKeyId: []byte{1, 2, 3, 4, 6},
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}

		atomic.AddUint64(nextID, 1)

		certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, err
		}

		certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caKey)
		if err != nil {
			return nil, err
		}

		certPEMBytes := new(bytes.Buffer)
		pem.Encode(certPEMBytes, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		})

		certPrivKeyPEMBytes := new(bytes.Buffer)
		pem.Encode(certPrivKeyPEMBytes, &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
		})

		if err := os.WriteFile(fmt.Sprintf(siteCertPath, sniSha1SumStr), certPEMBytes.Bytes(), 0o644); err != nil {
			return nil, err
		}

		if err := os.WriteFile(fmt.Sprintf(siteKeyPath, sniSha1SumStr), certPrivKeyPEMBytes.Bytes(), 0o644); err != nil {
			return nil, err
		}

		certPEM = certPEMBytes.Bytes()
		certPrivKeyPEM = certPrivKeyPEMBytes.Bytes()

	} else {
		var err error

		certPEM, err = os.ReadFile(fmt.Sprintf(siteCertPath, sniSha1SumStr))
		if err != nil {
			return nil, err
		}

		certPrivKeyPEM, err = os.ReadFile(fmt.Sprintf(siteKeyPath, sniSha1SumStr))
		if err != nil {
			return nil, err
		}
	}

	serverCert, err := tls.X509KeyPair(certPEM, certPrivKeyPEM)
	if err != nil {
		return nil, err
	}

	return &serverCert, nil
}

func main() {
	caCert, caKey, nextID, err := GetCA()
	if err != nil {
		panic(err)
	}

	tmpl := template.Must(template.ParseFS(indexHTML, "index.html"))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl.Execute(w, map[string]string{"url": r.Host})
	})

	group := singleflight.Group{}

	go func() {
		conf := &tls.Config{
			GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				cert, err, _ := group.Do(chi.ServerName, func() (any, error) {
					return GetSiteTLSCertificate(chi.ServerName, caCert, caKey, &nextID)
				})
				return cert.(*tls.Certificate), err
			},
		}

		listener, err := tls.Listen("tcp", ":443", conf)
		if err != nil {
			panic(err)
		}

		if err := http.Serve(listener, nil); err != nil {
			panic(err)
		}
	}()

	if err := http.ListenAndServe(":80", nil); err != nil {
		panic(err)
	}
}
