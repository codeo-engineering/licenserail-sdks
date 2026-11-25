package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	lr "github.com/codeo-engineering/licenserail-sdks/go"
)

func main() {
	pem, err := os.ReadFile(os.Getenv("LR_PUBLIC_KEY_FILE"))
	if err != nil {
		panic(err)
	}
	seconds, _ := strconv.Atoi(os.Getenv("LR_TIMEOUT"))
	o := lr.Options{ServerURL: os.Getenv("LR_URL"), Vendor: os.Getenv("LR_VENDOR"), Product: os.Getenv("LR_PRODUCT"), PublicKeyPEM: string(pem),
		StorageDir: os.Getenv("LR_STORAGE"), AppVersion: "1.2.3", Timeout: time.Duration(seconds) * time.Second}
	if d := strings.Split(os.Getenv("LR_DEVICE"), ","); len(d) == 4 {
		o.Fingerprint = func() lr.Fingerprint {
			return lr.Fingerprint{MachineID: d[0], DiskID: d[1], HostName: d[2], BoardID: d[3], OS: "linux"}
		}
	}
	client, err := lr.NewClient(o)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	out := map[string]interface{}{}
	put := func(r lr.Result) { out["success"], out["errorCode"], out["message"] = r.Success, r.ErrorCode, r.Message }
	switch os.Args[1] {
	case "activate":
		put(client.Activate(ctx, os.Args[2], ""))
	case "deactivate":
		put(client.Deactivate(ctx))
	case "refresh":
		err := client.Refresh(ctx, nil)
		out["success"] = err == nil
		if err != nil {
			out["errorCode"], out["message"] = "network", err.Error()
		}
	default:
		s := client.Check(ctx)
		features := []string{}
		if s.License != nil {
			features = append(features, s.License.Entitlements...)
			out["test"] = s.License.Test
		}
		out["status"], out["features"] = s.Status, features
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
