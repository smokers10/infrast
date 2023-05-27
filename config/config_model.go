package config

type Configuration struct {
	PostgreSQL  DatabasePostgreSQL `yaml:"postgres"`
	MongoDB     DatabaseMongoDB    `yaml:"mongodb"`
	Application Application        `yaml:"application"`
	SMTP        SMTP               `yaml:"smtp"`
}

type Application struct {
	Port   string `yaml:"port"`
	Secret string `yaml:"secret"`
}

type DatabasePostgreSQL struct {
	Host                  string `yaml:"host"`
	Port                  int    `yaml:"port"`
	User                  string `yaml:"user"`
	Password              string `yaml:"password"`
	DBName                string `yaml:"db_name"`
	MaxOpenConnections    int    `yaml:"max_open_connections"`
	MaxIdleConnections    int    `yaml:"max_idle_connections"`
	ConnectionMaxLifeTime int    `yaml:"connection_max_life_time"`
}

type DatabaseMongoDB struct {
	URI                string `yaml:"uri"`
	MaxPool            int    `yaml:"max_pool"`
	MinPool            int    `yaml:"min_pool"`
	MaxIdleConnections int    `yaml:"max_idle_connections"`
	DBName             string `yaml:"db_name"`
}

type SMTP struct {
	Host     string `yaml:"host"`
	Password string `yaml:"password"`
	Username string `yaml:"username"`
	Port     int    `yaml:"port"`
	Sender   string `yaml:"sender"`
}
