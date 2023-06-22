# go-infrastructure
A simpler way to setup infrastructure for your golang project!

## Provided Functionality
* Database (PostgreSQL & mongoDB)
* Encryption (Bcrypt)
* Json Web Token
* Identifier (Google Identifier)
* SMTP
* Mock Contract On Every Infra Except Databases
* Middleware (Work Only On Go-Fiber Framework Only)
* ACL (Access Control List)

## How To Access Every Sub Modules?
you can access every provided infrastructure by calling its function directly or use head function to access all infrastructure in singe function call, here step-by-step to use head function :
* Make configuration YAML (follow the prefered vonfiguration format below).
* Call head function on your project it will require configuration YAML file path.

### Prefered Configuration Format
```
application :
  port : ":8000"
  secret : "172y87f1"
postgres : 
  host : "localhost"
  port : 5432
  user : "testuser"
  password : "testpass"
  db_name : "testdb"
  max_open_connections : 1
  max_idle_connections : 2
  connection_max_life_time : 2
mongodb : 
  uri : "localhost/bla-bla-bla"
  max_pool : 10
  min_pool : 5
  max_idle_connections : 2
  db_name : "testdb"
smtp : 
  host : "localhost"
  password : "testpass"
  username : "testuser"
  port : 5432
  sender : "sender"
user_management :
  user_credential : [
    {
      type : "admin",
      user_table : "admins",
      credential : ["username", "email"],
      id_property : "id",
      photo_profile_property : "profile",
      password_property : "password",
      username_property : "username",
      email_property : "email",
      phone_property : "phone"
    },
    {
      type : "customer",
      user_table : "customers",
      credential : ["username", "email", "phone"],
      id_property : "id",
      photo_profile_property : "profile",
      password_property : "password",
      username_property : "username",
      email_property : "email",
      phone_property : "phone"
    },
  ]
  login : 
    table_name : "login"
    token_property : "token"
    failed_counter_property : "failed_attempt"
    type_property : "user_type"
    credential_property : "credential"
    login_at_property : "login_at"
    device_id_property : "device_id"
    attempt_at_property : "attempt_at"
    max_failed_attempt : 3
    login_block_duration : 300
    email_template_path : "template/login-security-concern.html"
  user_device : 
    table_name : "user_devices"
    id_property : "id"
    device_id_property : "device_id"
    user_id_property : "user_id"
    user_type_property : "user_type"
    email_template_path : "template/device-warning.html"
  registration : 
    table_name : "registration"
    id_property : "id"
    credential_property : "credential"
    token_property : "token"
    otp_property : "otp"
    registration_status_property : "status"
    device_id_property : "device_id"
    created_at_property : "created_at"
    email_template_path : "template/registration.html"
    user_type_property : "user_type"
  reset_password : 
    table_name : "reset_password"
    id_property : "id"
    token_property : "token"
    otp_property : "otp"
    credential_property : "credential"
    created_at_property : "created_at"
    validity_duration : 900000
    email_template_path : "template/forgot-password.html"
    user_type_property : "user_type"
```
## User Management
This feature can help you dealing with basic user management, This feature has functionality like :
* Login
* 3-Step Registration (input credential -> Verification -> Input Bio)
* Email / Phone Verification
* Reset Password

Note : feature not suitable for every case! i will make documentation about this later

### How to Use User Management

## How About Unit Testing ?
i made mock contract on every infrastructure except databases but you need to use Testify package to make it work, just in case you does'nt have Testify package on your project please run command:

```
$ go get github.com/stretchr/testify
```
if you already have Testify on your project it's good to go! see code example below:

```
func TestTest(t *testing.T) {
	mailerMock := contract.MailerContractMock{Mock: mock.Mock{}}
	h := head.ModuleHeader{
		Mailer: &mailerMock,
	}

	t.Run("Failed", func(t *testing.T) {
		mailerMock.Mock.On("Send", []string{mock.Anything}, mock.Anything, mock.Anything).Return(errors.New("error send email")).Once()
		_, err := Register(&h, mock.Anything)

		assert.NotEmpty(t, err)
		t.Logf("error send email : %v\n", err.Error())
	})
}

```

## Upcoming Feature
Here the list of my tech debt :
* Table Structure Checker (yaml table properties vs table structure from DB)
* Whatsapp integration (security concern, reset password and verification)
* Firebase integration
* Payment Gateway Integration
* Basic ACLS
* Middleware
* Go-Fiber Integration
