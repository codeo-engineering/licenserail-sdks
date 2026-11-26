package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func run(c *client, cmd string, a args) error {
	switch cmd {
	case "login":
		return login(c, a)
	case "logout":
		c.cfg.Token, c.cfg.Tenant, c.cfg.Tenants, c.cfg.Email, c.cfg.TokenIsKey = "", "", nil, "", false
		return c.cfg.save()
	case "whoami":
		return show(c, "GET", "/environment", nil)
	case "tenants":
		return tenants(c, a)
	case "env":
		return env(c, a)
	case "products":
		return crud(c, a, "products", []string{"id", "code", "name", "licenseCount"}, func(a args) map[string]interface{} {
			b := map[string]interface{}{}
			set(b, "code", a.get("code"))
			set(b, "name", a.get("name"))
			if v := a.get("offline-grace-days"); v != "" {
				n, _ := strconv.Atoi(v)
				b["offlineGraceDays"] = n
			}
			if m := meta(a); len(m) > 0 {
				b["metadata"] = m
			}
			return b
		})
	case "customers":
		return crud(c, a, "customers", []string{"id", "name", "email", "licenseCount"}, func(a args) map[string]interface{} {
			b := map[string]interface{}{}
			set(b, "name", a.get("name"))
			set(b, "email", a.get("email"))
			set(b, "contactName", a.get("contact"))
			set(b, "phone", a.get("phone"))
			set(b, "notes", a.get("notes"))
			if m := meta(a); len(m) > 0 {
				b["metadata"] = m
			}
			return b
		})
	case "features":
		return features(c, a)
	case "licenses":
		return licenses(c, a)
	case "activations":
		switch a.arg(0) {
		case "list":
			return list(c, "/licenses/"+a.get("license")+"/activations", []string{"id", "machineName", "os", "lastSeenAt", "active"})
		case "deactivate":
			confirm(a, c.cfg, "Removing a device")
			return show(c, "POST", "/activations/"+a.arg(1)+"/deactivate", nil)
		}
	case "events":
		return events(c, a)
	case "keys":
		switch a.arg(0) {
		case "list":
			return list(c, "/api-keys", []string{"id", "name", "prefix", "last4", "isAgent", "revokedAt"})
		case "create":
			body := map[string]interface{}{"name": a.get("name"), "isAgent": a.bools["agent"]}
			if a.bools["restricted"] {
				body["scopes"] = a.flags["scope"]
			}
			return show(c, "POST", "/api-keys", body)
		case "revoke":
			return show(c, "DELETE", "/api-keys/"+a.arg(1), nil)
		}
	case "webhooks":
		switch a.arg(0) {
		case "list":
			return list(c, "/webhook-endpoints", []string{"id", "url", "enabled", "eventTypes"})
		case "create":
			return show(c, "POST", "/webhook-endpoints", map[string]interface{}{"url": a.get("url"), "eventTypes": a.flags["event"]})
		case "test":
			return show(c, "POST", "/webhook-endpoints/"+a.arg(1)+"/test", nil)
		case "deliveries":
			return list(c, "/webhook-endpoints/"+a.arg(1)+"/deliveries", []string{"id", "eventType", "status", "attempt", "responseCode"})
		case "delete":
			confirm(a, c.cfg, "Deleting a webhook endpoint")
			return show(c, "DELETE", "/webhook-endpoints/"+a.arg(1), nil)
		}
	case "public-key":
		r, err := c.do("GET", "/environment/public-key", nil)
		if err != nil {
			return err
		}
		if a.bools["pem"] {
			fmt.Print(r["publicKeyPem"])
			return nil
		}
		c.print(r)
		return nil
	case "test":
		if a.arg(0) == "activate" {
			body := map[string]interface{}{}
			set(body, "productCode", a.get("product"))
			set(body, "licenseKey", a.get("key"))
			return show(c, "POST", "/test/activate", body)
		}
	case "init":
		return initCode(c, a)
	case "mcp":
		return mcpConfig(c, a)
	case "billing":
		return billing(c, a)
	case "docs":
		if a.arg(0) == "search" {
			r, err := c.do("GET", "/docs/search"+q(map[string]string{"q": strings.Join(a.pos[1:], " ")}), nil)
			if err != nil {
				return err
			}
			if c.json {
				c.print(r)
				return nil
			}
			for _, h := range r["data"].([]interface{}) {
				m := h.(map[string]interface{})
				fmt.Printf("# %v\n%v\n\n%v\n\n", m["title"], m["url"], m["snippet"])
			}
			return nil
		}
	}
	usage()
	return fmt.Errorf("unknown command: %s %s", cmd, a.arg(0))
}

func set(m map[string]interface{}, k, v string) {
	if v != "" {
		m[k] = v
	}
}

func show(c *client, method, path string, body interface{}) error {
	r, err := c.do(method, path, body)
	if err != nil {
		return err
	}
	c.print(r)
	return nil
}

func list(c *client, path string, columns []string) error {
	r, err := c.do("GET", path, nil)
	if err != nil {
		return err
	}
	c.print(r, columns...)
	return nil
}

func crud(c *client, a args, resource string, columns []string, body func(args) map[string]interface{}) error {
	path := "/" + resource
	switch a.arg(0) {
	case "list", "":
		return list(c, path+q(map[string]string{"q": a.get("q"), "limit": a.get("limit"), "startingAfter": a.get("starting-after")}), columns)
	case "get":
		return show(c, "GET", path+"/"+a.arg(1), nil)
	case "create":
		return show(c, "POST", path, body(a))
	case "update":
		return show(c, "PATCH", path+"/"+a.arg(1), body(a))
	case "delete":
		confirm(a, c.cfg, "Deleting")
		return show(c, "DELETE", path+"/"+a.arg(1), nil)
	}
	return fmt.Errorf("unknown %s command %q", resource, a.arg(0))
}

func features(c *client, a args) error {
	product := a.get("product")
	switch a.arg(0) {
	case "list":
		return list(c, "/products/"+product+"/features", []string{"id", "code", "name"})
	case "create":
		return show(c, "POST", "/products/"+product+"/features", map[string]interface{}{"code": a.get("code"), "name": firstNonEmpty(a.get("name"), a.get("code"))})
	case "delete":
		confirm(a, c.cfg, "Deleting a feature")
		return show(c, "DELETE", "/products/"+product+"/features/"+a.arg(1), nil)
	}
	return fmt.Errorf("unknown features command %q", a.arg(0))
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func licenses(c *client, a args) error {
	id := a.arg(1)
	switch a.arg(0) {
	case "list", "":
		return list(c, "/licenses"+q(map[string]string{"productId": a.get("product"), "customerId": a.get("customer"), "status": a.get("status"),
			"q": a.get("q"), "limit": a.get("limit"), "startingAfter": a.get("starting-after")}),
			[]string{"id", "key", "status", "activeActivations", "maxActivations", "expiresAt"})
	case "get":
		return show(c, "GET", "/licenses/"+id, nil)
	case "create":
		body := map[string]interface{}{"productId": a.get("product"), "customerId": a.get("customer")}
		set(body, "kind", a.get("kind"))
		set(body, "licensee", a.get("licensee"))
		set(body, "notes", a.get("notes"))
		if e := a.get("expires"); e != "" {
			body["expiresAt"] = expires(e)
		}
		for flag, field := range map[string]string{"seats": "maxActivations", "lease-minutes": "leaseMinutes", "count": "quantity"} {
			if v := a.get(flag); v != "" {
				n, _ := strconv.Atoi(v)
				body[field] = n
			}
		}
		if a.bools["floating"] {
			body["isFloating"] = true
		}
		if f := a.flags["feature"]; len(f) > 0 {
			body["features"] = f
		}
		if m := meta(a); len(m) > 0 {
			body["metadata"] = m
		}
		r, err := c.do("POST", "/licenses", body)
		if err != nil {
			return err
		}
		if c.json {
			c.print(r)
			return nil
		}
		for _, l := range r["data"].([]interface{}) {
			m := l.(map[string]interface{})
			fmt.Printf("%v  %v\n", m["key"], m["id"])
		}
		return nil
	case "update":
		body := map[string]interface{}{}
		if e, ok := a.flags["expires"]; ok {
			body["expiresAt"] = expires(e[len(e)-1])
		}
		if v := a.get("seats"); v != "" {
			n, _ := strconv.Atoi(v)
			body["maxActivations"] = n
		}
		if f, ok := a.flags["feature"]; ok {
			body["features"] = f
		}
		if m := meta(a); len(m) > 0 {
			body["metadata"] = m
		}
		set(body, "notes", a.get("notes"))
		set(body, "licensee", a.get("licensee"))
		set(body, "kind", a.get("kind"))
		return show(c, "PATCH", "/licenses/"+id, body)
	case "suspend", "resume":
		return show(c, "POST", "/licenses/"+id+"/"+a.arg(0), nil)
	case "revoke":
		confirm(a, c.cfg, "Revoking a license (irreversible)")
		return show(c, "POST", "/licenses/"+id+"/revoke", nil)
	case "transfer":
		return show(c, "POST", "/licenses/"+id+"/transfer", map[string]interface{}{"customerId": a.get("customer")})
	case "delete":
		confirm(a, c.cfg, "Deleting a license")
		return show(c, "DELETE", "/licenses/"+id, nil)
	}
	return fmt.Errorf("unknown licenses command %q", a.arg(0))
}

func events(c *client, a args) error {
	if a.arg(0) != "tail" {
		return list(c, "/events"+q(map[string]string{"type": a.get("type"), "limit": a.get("limit")}), []string{"id", "type", "createdAt"})
	}
	seen := map[string]bool{}
	first := true
	for {
		r, err := c.do("GET", "/events"+q(map[string]string{"type": a.get("type"), "limit": "50"}), nil)
		if err != nil {
			return err
		}
		data, _ := r["data"].([]interface{})
		for i := len(data) - 1; i >= 0; i-- {
			m := data[i].(map[string]interface{})
			id := fmt.Sprint(m["id"])
			if seen[id] {
				continue
			}
			seen[id] = true
			if first {
				continue
			}
			if c.json {
				b, _ := json.Marshal(m)
				fmt.Println(string(b))
			} else {
				fmt.Printf("%v  %v  %v\n", m["createdAt"], m["type"], id)
			}
		}
		first = false
		time.Sleep(5 * time.Second)
	}
}

func tenants(c *client, a args) error {
	switch a.arg(0) {
	case "list", "":
		for _, t := range c.cfg.Tenants {
			mark := " "
			if t.ID == c.cfg.Tenant {
				mark = "*"
			}
			fmt.Printf("%s %s  %s  (%s)\n", mark, t.Slug, t.Name, t.Role)
		}
		return nil
	case "use":
		for _, t := range c.cfg.Tenants {
			if t.Slug == a.arg(1) || t.ID == a.arg(1) {
				c.cfg.Tenant = t.ID
				fmt.Printf("Using %s.\n", t.Name)
				return c.cfg.save()
			}
		}
		return fmt.Errorf("no organization %q (run `licenserail tenants list`)", a.arg(1))
	}
	return fmt.Errorf("unknown tenants command %q", a.arg(0))
}

func env(c *client, a args) error {
	switch a.arg(0) {
	case "use":
		if a.arg(1) != "live" && a.arg(1) != "test" {
			return errors.New("environment must be live or test")
		}
		c.cfg.Environment = a.arg(1)
		if a.arg(1) == "live" && !c.cfg.TokenIsKey {
			fmt.Println("Note: CLI sessions work in Test. For Live, create a Live API key in the dashboard and run `licenserail login --token <key>`.")
		}
		return c.cfg.save()
	default:
		fmt.Println(c.cfg.Environment)
		return nil
	}
}

func login(c *client, a args) error {
	if token := a.get("token"); token != "" {
		c.cfg.Token, c.cfg.TokenIsKey = token, true
		if err := c.cfg.save(); err != nil {
			return err
		}
		return show(c, "GET", "/environment", nil)
	}
	if a.bools["live"] {
		fmt.Println("Live access for agents and the CLI goes through Live API keys: create one in the dashboard (API keys page),")
		fmt.Println("then run `licenserail login --token lr_live_...`. Irreversible Live actions still ask a person to approve.")
		return nil
	}
	email := a.get("email")
	in := bufio.NewReader(os.Stdin)
	if email == "" {
		fmt.Print("Email: ")
		line, _ := in.ReadString('\n')
		email = strings.TrimSpace(line)
	}
	r, err := c.do("POST", "/api/auth/login-code", map[string]interface{}{"email": email, "purpose": "cli"})
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "We emailed a 6-digit code to %s.\nCode: ", email)
	line, _ := in.ReadString('\n')
	res, err := c.do("POST", "/api/auth/login-code/verify", map[string]interface{}{"loginId": r["loginId"], "code": strings.TrimSpace(line)})
	if err != nil {
		return err
	}
	c.cfg.Token, c.cfg.TokenIsKey, c.cfg.Email, c.cfg.Environment = fmt.Sprint(res["userToken"]), false, email, "test"
	c.cfg.Tenants = nil
	if list, ok := res["tenants"].([]interface{}); ok {
		for _, t := range list {
			m := t.(map[string]interface{})
			c.cfg.Tenants = append(c.cfg.Tenants, tenantRef{fmt.Sprint(m["id"]), fmt.Sprint(m["name"]), fmt.Sprint(m["slug"]), fmt.Sprint(m["role"])})
		}
	}
	c.cfg.Tenant = fmt.Sprint(res["tenantId"])
	if err := c.cfg.save(); err != nil {
		return err
	}
	if c.json {
		c.print(res)
		return nil
	}
	fmt.Printf("Signed in as %s (Test environment).\n", email)
	if key, ok := res["testApiKey"].(string); ok && key != "" {
		fmt.Printf("Your organization was created. Test API key (shown once): %s\n", key)
	}
	fmt.Println("Next: licenserail products create --code my-app --name \"My App\"")
	return nil
}

func initCode(c *client, a args) error {
	body := map[string]interface{}{"language": a.arg(0)}
	set(body, "productCode", a.get("product"))
	r, err := c.do("POST", "/integration-code", body)
	if err != nil {
		return err
	}
	if c.json {
		c.print(r)
		return nil
	}
	fmt.Printf("# Install\n%v\n\n# Code\n%v\n\n# Notes\n%v\n", r["install"], r["code"], r["notes"])
	return nil
}

func mcpConfig(c *client, a args) error {
	server := strings.TrimRight(c.cfg.APIURL, "/") + "/mcp"
	switch a.get("client") {
	case "cursor", "vscode":
		fmt.Printf("{\n  \"servers\": {\n    \"licenserail\": { \"type\": \"http\", \"url\": %q }\n  }\n}\n", server)
	default:
		fmt.Printf("claude mcp add --transport http licenserail %s\n", server)
	}
	fmt.Fprintln(os.Stderr, "The client signs in through your browser (OAuth); access is Test-only unless you allow Live on the consent page.")
	return nil
}

func billing(c *client, a args) error {
	switch a.arg(0) {
	case "balance", "":
		return show(c, "GET", "/billing/balance", nil)
	case "usage":
		return list(c, "/billing/usage", []string{"day", "environment", "meter", "count", "amountMicro"})
	case "top-up":
		dollars, err := strconv.ParseFloat(a.arg(1), 64)
		if err != nil {
			return errors.New("usage: licenserail billing top-up <dollars>")
		}
		r, err := c.do("POST", "/billing/top-ups", map[string]interface{}{"amountMicro": int64(dollars*100) * 10000})
		if err != nil {
			return err
		}
		checkout := fmt.Sprint(r["checkoutUrl"])
		fmt.Println("Complete the payment in your browser:", checkout)
		openBrowser(checkout)
		return nil
	}
	return fmt.Errorf("unknown billing command %q", a.arg(0))
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	_ = cmd.Start()
}
