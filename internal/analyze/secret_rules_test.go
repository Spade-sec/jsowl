package analyze

import (
	"strings"
	"testing"

	"github.com/youmulijiang/jsowl/internal/model"
)

func TestSensitiveConfigurationCapturesLiteralValues(t *testing.T) {
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ rule, body, value string }{
		{"凭据字段值", `{"password":"DemoPassword_123"}`, "DemoPassword_123"},
		{"凭据字段值", `pass = 'DemoPassword_123'`, "DemoPassword_123"},
		{"凭据字段值", `"passwd": "DemoPassword_123"`, "DemoPassword_123"},
		{"凭据字段值", `mima: 'DemoPassword_123'`, "DemoPassword_123"},
		{"凭据字段值", "password = `DemoPassword_123`", "DemoPassword_123"},
		{"凭据字段值", `token = "DemoToken_123456"`, "DemoToken_123456"},
		{"凭据字段值", `"refresh_token": "DemoRefresh_123456"`, "DemoRefresh_123456"},
		{"凭据字段值", `"custom_token": "DemoCustom_123456"`, "DemoCustom_123456"},
		{"凭据字段值", `"access_key_id": "DemoAccess_123456"`, "DemoAccess_123456"},
		{"凭据字段值", `"access_key_secret": "DemoAccessSecret_123456"`, "DemoAccessSecret_123456"},
		{"通用敏感-key-value", `"secret_id": "DemoSecretId_123456"`, "DemoSecretId_123456"},
		{"通用敏感-key-value", `"app_secret": "DemoAppSecret_123456"`, "DemoAppSecret_123456"},
		{"云账号配置值", `"account_sid": "DemoSID_123456"`, "DemoSID_123456"},
		{"私钥标识", `"private_key_id": "DemoPrivate_123456"`, "DemoPrivate_123456"},
		{"华为oss凭据", `"huawei.oss.ak": "DemoHuawei_123456"`, "DemoHuawei_123456"},
		{"用户名字段值", `"username": "admin-user"`, "admin-user"},
		{"openid-或-appsecret", `"appsecret": "DemoAppSecret_123456"`, "DemoAppSecret_123456"},
		{"加密密钥配置值", `"encryptkey": "DemoEncrypt_123456"`, "DemoEncrypt_123456"},
		{"加密密钥配置值", `"aes_key": "DemoAES_123456"`, "DemoAES_123456"},
	}
	for _, test := range cases {
		t.Run(test.body, func(t *testing.T) {
			id := "hae.密钥凭证." + test.rule
			findings, _ := engine.Analyze(ResourceRef{URL: "config.js"}, []byte(test.body))
			finding, ok := findingByRule(findings, id)
			if !ok || finding.Value != test.value {
				t.Fatalf("expected %s = %q; got %+v", id, test.value, findings)
			}
		})
	}
}

func TestSensitiveConfigurationRejectsDynamicAndPlaceholderValues(t *testing.T) {
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	bodies := []string{
		`password = suppliedPassword`, `token: getToken()`, `password: process.env.PASSWORD`,
		`token: import.meta.env.TOKEN`, `password: ""`, `password: "changeme"`,
		`password: "YOUR_PASSWORD_HERE"`, `token: "<TOKEN>"`, `secret: "***"`,
		`password: "process.env.PASSWORD"`, `token: "{{TOKEN}}"`,
		"password: `${process.env.PASSWORD}`", `"appsecret": "${APP_SECRET}"`,
		`"huawei.oss.ak": "${HUAWEI_AK}"`, `"private_key_id": "undefined"`,
		`"passwordEnabled": "enabled"`, `"notpassword": "DemoPassword_123"`,
		`password: "unterminated`, `password: "mismatched'`,
	}
	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			findings, _ := engine.Analyze(ResourceRef{URL: "config.js"}, []byte(body))
			for _, finding := range findings {
				if strings.HasPrefix(finding.RuleID, "hae.密钥凭证.") {
					t.Fatalf("false credential finding: %+v", finding)
				}
			}
		})
	}
}

func TestRuleConfigurationContainsNoURLRulesAndAPIsStillExtract(t *testing.T) {
	for _, rule := range DefaultRules() {
		if rule.Category == model.RuleCategoryURL {
			t.Fatalf("URL rule remains in configuration: %s", rule.ID)
		}
	}
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`fetch('/api/users')`, `xhr.open('POST', '/api/users')`, `const url = 'https://example.test/api/users'`} {
		_, candidates := engine.Analyze(ResourceRef{URL: "app.js"}, []byte(body))
		if len(candidates) == 0 {
			t.Fatalf("code-owned API extraction stopped working: %s", body)
		}
		for _, candidate := range candidates {
			if strings.HasPrefix(candidate.RuleID, "hae.") {
				t.Fatalf("unexpected configured URL candidate: %+v", candidate)
			}
		}
	}
}
