package analyze

import "testing"

func TestDatabaseConnectionRules(t *testing.T) {
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ rule, value string }{
		{"数据库账密uri", "mysql://alice:DemoPass_123@db.example.test:3306/app?charset=utf8mb4"},
		{"数据库账密uri", "mysql+pymysql://alice:DemoPass_123@db.example.test/app"},
		{"数据库账密uri", "postgresql://alice:p%40ss@db.example.test:5432/app?sslmode=require"},
		{"数据库账密uri", "postgres://alice:DemoPass_123@[2001:db8::1]:5432/app"},
		{"数据库账密uri", "mongodb+srv://alice:DemoPass_123@cluster.example.test/app?retryWrites=true"},
		{"数据库账密uri", "mongodb://alice:DemoPass_123@db1:27017,db2:27017/app"},
		{"数据库账密uri", "redis://:DemoPass_123@cache.example.test:6379/0"},
		{"数据库账密uri", "rediss://default:DemoPass_123@cache.example.test:6380/0"},
		{"数据库账密uri", "mssql://sa:DemoPass_123@db.example.test:1433/app"},
		{"数据库账密uri", "oracle://alice:DemoPass_123@db.example.test:1521/service"},
		{"数据库连接地址", "mysql://db.example.test:3306/app"},
		{"数据库连接地址", "mongodb://db1:27017,db2:27017/app"},
		{"数据库连接地址", "redis://localhost:6379/0"},
		{"jdbc-连接串", "jdbc:mysql://db.example.test:3306/app?user=alice&password=DemoPass_123"},
		{"jdbc-连接串", "jdbc:sqlserver://db.example.test:1433;databaseName=app;user=sa;password=DemoPass_123;"},
		{"jdbc-连接串", "jdbc:oracle:thin:@//db.example.test:1521/service"},
		{"jdbc-连接串", "jdbc:oracle:thin:@db.example.test:1521:ORCL"},
		{"jdbc-连接串", "jdbc:h2:mem:app;DB_CLOSE_DELAY=-1"},
		{"jdbc-连接串", "jdbc:sqlite:/data/app.db"},
		{"数据库参数连接串", "Server=db.example.test;Database=app;User Id=sa;Password=DemoPass_123;"},
		{"数据库参数连接串", "Host=db.example.test;Port=5432;Database=app;Username=alice;Password=DemoPass_123;"},
		{"数据库参数连接串", "Data Source=db.example.test;Initial Catalog=app;UID=sa;PWD=DemoPass_123;"},
		{"mysql-go-dsn", "alice:DemoPass_123@tcp(127.0.0.1:3306)/app?charset=utf8mb4&parseTime=True"},
		{"mysql-go-dsn", "alice:DemoPass_123@unix(/tmp/mysql.sock)/app"},
	}
	for _, test := range cases {
		t.Run(test.value, func(t *testing.T) {
			findings, _ := engine.Analyze(ResourceRef{URL: "config.js"}, []byte(`const connection = "`+test.value+`";`))
			id := "hae.密钥凭证." + test.rule
			finding, ok := findingByRule(findings, id)
			if !ok || finding.Value != test.value {
				t.Fatalf("expected %s = %q, got %+v", id, test.value, findings)
			}
			if test.rule == "数据库账密uri" && hasRule(findings, "hae.密钥凭证.数据库连接地址") {
				t.Fatal("credential URI also reported as an address")
			}
			if test.rule == "jdbc-连接串" && hasRule(findings, "hae.密钥凭证.数据库连接地址") {
				t.Fatal("JDBC URI also reported as a partial address")
			}
		})
	}
}

func TestDatabaseRulesRejectOrdinaryURLsAndIncompleteConnections(t *testing.T) {
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`"https://example.test/api/mysql"`, `"postgresql"`, `"mysql://"`,
		`"mysql://alice:password@"`, `"redis://cache.example.test:6379/0"`,
		`"mysql://alice:${DB_PASSWORD}@db.example.test/app"`,
		`"jdbc:mysql://${DB_HOST}/app"`,
		`"Server=db.example.test;Database=app;Integrated Security=True;"`,
		`"Server=db.example.test;Database=app;Password=;"`,
		`"Server=db.example.test;Database=app;Password=${DB_PASSWORD};"`,
		`"alice:${DB_PASSWORD}@tcp(db.example.test:3306)/app"`,
		`"Password=DemoPass_123;"`, `"alice@example.test"`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			findings, _ := engine.Analyze(ResourceRef{URL: "config.js"}, []byte(body))
			ids := []string{"数据库账密uri", "数据库参数连接串", "mysql-go-dsn"}
			if body != `"redis://cache.example.test:6379/0"` {
				ids = append(ids, "数据库连接地址", "jdbc-连接串")
			}
			for _, id := range ids {
				if hasRule(findings, "hae.密钥凭证."+id) {
					t.Fatalf("unexpected %s: %+v", id, findings)
				}
			}
		})
	}
}
