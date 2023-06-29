# go-infrastructure
A simpler way to setup infrastructure for your golang project!

## Provided Modules And Other
* Database (Postgre & mongoDB)
* Encryption (Bcrypt)
* Json Web Token
* Identifier (Google Identifier)
* SMTP
* Mock Contract
* Middleware
* Whatsapp Notification (Security Concern, Verification, Reset Password, etc)
* Firebase
* Payment Gateway (Midtrans)

## How To Access Every Sub Modules?
you can access every provided sub modules by calling its function directly or use head function to access all sub modules in singe function call, here step-by-step to use head function :
* Make configuration YAML (follow the prefered vonfiguration format below).
* Call head function on your project it will require configuration YAML file path.

## Basic Configuration
The basic configuration will accomodate configuration for basic module such as application, database, smtp, WA, and payment gateway. See YAML bellow :

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
```

## User Management
This feature can help you dealing with basic user management, This feature has functionality like :
* Login
* 3-Step Registration (input credential (email / phone) -> Verification -> Input Bio)
* Reset Password
* Device ID (mobile & web) Based Authentication

### User Management Preparation
We documented this configuration separately from basic configuration. In order to make user management feature work perfectly you need to follow certain rules:
1. You need to create certain table on your database (user, login, registration, user device, reset_password)
2. every table must have certain property

### User Management Configuration
```
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

### 1. User Credential
user credential is configuration to define user table i.e users, customers or admins so system can access it to do some data reading and basic manipulation. In order to make it work you must have following properties on your table:
* id
* photo profile
* password
* username
* email
* phone

other than that there is also neccesary configuration that you must set like : 
* type -> this used to identify type of user on middleware level
* credential -> this work like marker on credential properties, for example if you want your system has ability to login with using username & email you can set credential like this:
```
{
  credential : ["username", "email"]
}
```
### 2. Login
This configuration is used to make system recognized which login table. Here the list of table properties you must have on your login table :
* token
* failed counter / failed attempt
* user type 
* credential 
* device id
* logged at
* attempted at

other than that there is also neccesary login configuration you must set :
* max failed attempt -> this is threshold of how many failed login attempt 
* login block duration -> this is where you define login suspension timeout
* email template path -> this is used to define security email template path

### 3. User Device
This configuration to set user device table to stire device id that user has. Here the list of table properties your must have on your user device table:
* id
* device id
* user id
* user type

Other than that there also neccesary user device configuration you must set :
* email_template_path -> this value is used when user login on another device system will send security concern mail to confirm whether device is owned by user or not :

### 4. Registration
This configuration is used to make system able to reconize which registration table. Here the table properties you must have on your registration table :
* id
* credential
* token
* otp
* status
* device id
* created at 
* user type

Other than that here the configuration you must set :
* email template path -> this value is used when new user registered to your system

## 5. Reset Password
This configuration is used to make system reconized which is reset password table. Here the table properties you must have on you forgot password table
* id
* token
* otp
* credential 
* created at
* user type

Other than that here other neccesary configuration you must set :
* validity duration - this value hold how long reset password is valid in second
* email template path - this value is used when user request reset password session so system will be able to send reset password OTP to registered user email

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
* Whatsapp
* Firebase
* Payment Gateway Integration (Midtrans)
