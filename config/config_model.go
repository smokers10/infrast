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

type UserManagementConfig struct {
	Users              []User              `yaml:"users"`
	Login              LoginConfig         `yaml:"login"`
	Registration       RegistrationConfig  `yaml:"registration"`
	ResetPassword      ResetPasswordConfig `yaml:"reset_password"`
	UserDevice         UserDeviceConfig    `yaml:"user_device"`
	UserFCMToken       UserFCMTokenConfig  `yaml:"user_fcm_token"`
	MessageTemplate    MessageTemplate     `yaml:"message_template"`
	SelectedCredential User
}

type MessageTemplate struct {
	NewRegistrationEmailTemplatePath  string `yaml:"new_registration_email_template_path"`
	NewDeviceWarningEmailTemplatePath string `yaml:"new_device_warning_email_template_path"`
	ForgotPasswordEmailTemplatePath   string `yaml:"forgot_password_email_template_path"`
	NewRegistrationMessageTemplate    string `yaml:"new_registration_message_template"`
	NewDeviceWarningMessageTemplate   string `yaml:"new_device_warning_message_template"`
	ForgotPasswordMessageTemplate     string `yaml:"forgot_password_message_template"`
	LoginCancelationURL               string `yaml:"login_cancelation_url"`
}

type User struct {
	Type                 string   `yaml:"type"`
	UserTable            string   `yaml:"user_table"`
	Credential           []string `yaml:"credential"`
	IDProperty           string   `yaml:"id_property"`
	PhotoProfileProperty string   `yaml:"photo_profile_property"`
	PasswordProperty     string   `yaml:"password_property"`
	UsernameProperty     string   `yaml:"username_property"`
	EmailProperty        string   `yaml:"email_property"`
	PhoneProperty        string   `yaml:"phone_property"`
}

type LoginConfig struct {
	TableName             string `yaml:"table_name"`
	TokenProperty         string `yaml:"token_property"`
	FailedCounterProperty string `yaml:"failed_counter_property"`
	TypeProperty          string `yaml:"type_property"`
	CredentialProperty    string `yaml:"credential_property"`
	LoginAtProperty       string `yaml:"login_at_property"`
	DeviceIDProperty      string `yaml:"device_id_property"`
	MaxFailedAttempt      int    `yaml:"max_failed_attempt"`
	LoginBlockDuration    int    `yaml:"login_block_duration"`
	AttemptAtProperty     string `yaml:"attempt_at_property"`
}

type RegistrationConfig struct {
	TableName                  string `yaml:"table_name"`
	IDProperty                 string `yaml:"id_property"`
	CredentialProperty         string `yaml:"credential_property"`
	TokenProperty              string `yaml:"token_property"`
	OTPProperty                string `yaml:"otp_property"`
	RegistrationStatusProperty string `yaml:"registration_status_property"`
	DeviceIDProperty           string `yaml:"device_id_property"`
	UserTypeProperty           string `yaml:"user_type_property"`
	CreatedAtProperty          string `yaml:"created_at_property"`
	FCMTokenProperty           string `yaml:"fcm_token_property"`
}

type UserFCMTokenConfig struct {
	TableName         string `yaml:"table_name"`
	IDProperty        string `yaml:"id_property"`
	TokenProperty     string `yaml:"token_property"`
	TimestampProperty string `yaml:"timestamp_property"`
	UserTypeProperty  string `yaml:"user_type_property"`
	UserIDProperty    string `yaml:"user_id_property"`
}

type ResetPasswordConfig struct {
	TableName          string `yaml:"table_name"`
	IDProperty         string `yaml:"id_property"`
	TokenProperty      string `yaml:"token_property"`
	OTPProperty        string `yaml:"otp_property"`
	CredentialProperty string `yaml:"credential_property"`
	CreatedAtProperty  string `yaml:"created_at_property"`
	ValidityDuration   int    `yaml:"validity_duration"`
	UserTypeProperty   string `yaml:"user_type_property"`
}

type UserDeviceConfig struct {
	TableName        string `yaml:"table_name"`
	IDProperty       string `yaml:"id_property"`
	DeviceIDProperty string `yaml:"device_id_property"`
	UserIDProperty   string `yaml:"user_id_property"`
	UserTypeProperty string `yaml:"user_type_property"`
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
	Application    Application          `yaml:"application"`
	PostgreSQL     []PostgresConfig     `yaml:"postgres"`
	MongoDB        []MongoDBConfig      `yaml:"mongodb"`
	SMTP           SMTPConfig           `yaml:"smtp"`
	Midtrans       Midtrans             `yaml:"midtrans"`
	Whatsapp       Whatsapp             `yaml:"whatsapp"`
	Firebase       Firebase             `yaml:"firebase"`
	UserManagement UserManagementConfig `yaml:"user_management"`
}
