package analyze

import "testing"

func TestExtendedSensitiveConfigurationFields(t *testing.T) {
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const id = "hae.密钥凭证.扩展敏感配置你"
	const value = "DemoSecret_123=-"
	positive := []string{
		`client_secret = "DemoSecret_123=-"`,
		`{"algolia_admin_key":"DemoSecret_123=-"}`,
		`'cloudinary_api_secret': 'DemoSecret_123=-'`,
		`AWSSecretKey := "DemoSecret_123=-"`,
		`env.heroku_api_key => "DemoSecret_123=-"`,
		`encryption_password ||: "DemoSecret_123=-"`,
		`conn.login <= "DemoSecret_123=-"`,
		`eureka.awssecretkey > "DemoSecret_123=-"`,
		`docker_password_prod = "DemoSecret_123=-"`,
	}
	for _, body := range positive {
		t.Run(body, func(t *testing.T) {
			findings, _ := engine.Analyze(ResourceRef{URL: "config.js"}, []byte(body))
			finding, ok := findingByRule(findings, id)
			if !ok || finding.Value != value {
				t.Fatalf("expected only credential value %q, got %+v", value, findings)
			}
		})
	}
	negative := []string{
		`client_secret = variableName`,
		`client_secret = "short"`,
		`client_secret = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABC"`,
		`client_secret = "DemoSecret_123=-'`,
		`client_secret = "${ENV_SECRET}"`,
		`envXheroku_api_key = "DemoSecret_123=-"`,
		`connXlogin = "DemoSecret_123=-"`,
		`notclient_secret = "DemoSecret_123=-"`,
	}
	for _, body := range negative {
		t.Run(body, func(t *testing.T) {
			findings, _ := engine.Analyze(ResourceRef{URL: "config.js"}, []byte(body))
			if hasRule(findings, id) {
				t.Fatalf("extended rule matched %q", body)
			}
		})
	}
}
