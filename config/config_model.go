package config

type Application struct {
	Port                   string `yaml:"port"`
	Secret                 string `yaml:"secret"`
	UserManagementInstance string `yaml:"user_management_instance"`
	UserStorageInstance    string `yaml:"user_storage_instance"`
}

type PostgresConfig struct {
	Label                 string `yaml:"label"`
	Host                  string `yaml:"host"`
	Port                  int    `yaml:"port"`
	User                  string `yaml:"user"`
	Password              string `yaml:"password"`
	DBName                string `yaml:"db_name"`
	MaxOpenConnections    int    `yaml:"max_open_connections"`
	MaxIdleConnections    int    `yaml:"max_idle_connections"`
	ConnectionMaxLifeTime int    `yaml:"connection_max_life_time"`
}

type MongoDBConfig struct {
	Label              string `yaml:"label"`
	URI                string `yaml:"uri"`
	MaxPool            int    `yaml:"max_pool"`
	MinPool            int    `yaml:"min_pool"`
	MaxIdleConnections int    `yaml:"max_idle_connections"`
	DBName             string `yaml:"db_name"`
}

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
	Username string `yaml:"username"`
	Port     int    `yaml:"port"`
	Sender   string `yaml:"sender"`
}

type Midtrans struct {
	ServerKey       string   `yaml:"server_key"`
	IrisKey         string   `yaml:"iris_key"`
	Environment     string   `yaml:"environment"`
	EnabledPayments []string `yaml:"enabled_payments"`
}

type Whatsapp struct {
	SID       string `yaml:"sid"`
	AuthToken string `yaml:"auth_token"`
	Sender    string `yaml:"sender"`
}

type Firebase struct {
	ServiceAccountKey string `yaml:"service_account_key"`
}

type Configuration struct {
	Application Application      `yaml:"application"`
	PostgreSQL  []PostgresConfig `yaml:"postgres"`
	MongoDB     []MongoDBConfig  `yaml:"mongodb"`
	SMTP        SMTPConfig       `yaml:"smtp"`
	Midtrans    Midtrans         `yaml:"midtrans"`
	Whatsapp    Whatsapp         `yaml:"whatsapp"`
	Firebase    Firebase         `yaml:"firebase"`
}
