package analyze

import "testing"

func TestURLEmbeddedCredentials(t *testing.T) {
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const id = "hae.网络信息.url内嵌账密"
	positive := []struct{ body, value string }{
		{
			`const u = "https://svc:Passw0rd@example.com/api/users";`,
			"https://svc:Passw0rd@example.com/api/users",
		},
		{
			`fetch("http://admin:p%40ss@10.20.30.40:8080/login")`,
			"http://admin:p%40ss@10.20.30.40:8080/login",
		},
		{
			`const u = "ftp://deploy:secret@files.example.com/dir/file.txt";`,
			"ftp://deploy:secret@files.example.com/dir/file.txt",
		},
		{
			`const u = "wss://token:secret@ws.example.com/socket";`,
			"wss://token:secret@ws.example.com/socket",
		},
		{
			`const u = "https://user:pa:ss@[2001:db8::1]:8443/x";`,
			"https://user:pa:ss@[2001:db8::1]:8443/x",
		},
	}
	for _, test := range positive {
		t.Run(test.body, func(t *testing.T) {
			findings, _ := engine.Analyze(ResourceRef{URL: "config.js"}, []byte(test.body))
			finding, ok := findingByRule(findings, id)
			if !ok || finding.Value != test.value {
				t.Fatalf("expected %s = %q; got %+v", id, test.value, findings)
			}
		})
	}

	negative := []string{
		// userinfo must start the authority, not appear inside the path.
		`const u = "https://example.com/user:pass@x";`,
		// a username without a password is not an embedded credential pair.
		`const u = "https://user@example.com";`,
		// database URIs belong to hae.密钥凭证.数据库账密URI.
		`const u = "mongodb://svc:Passw0rd@10.0.0.1/orders";`,
		`const u = "http://user:pass@";`,
		`const u = "user:pass@example.com";`,
	}
	for _, body := range negative {
		t.Run(body, func(t *testing.T) {
			findings, _ := engine.Analyze(ResourceRef{URL: "config.js"}, []byte(body))
			if hasRule(findings, id) {
				t.Fatalf("unexpected embedded-credential finding for %q: %+v", body, findings)
			}
		})
	}
}
