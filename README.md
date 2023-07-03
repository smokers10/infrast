# GO INFRAST!
A simpler way to setup infrastructure for your golang project!

# Provided Module
here the module we provided for your project :
* Database (Postgre & Mongo)
* Encryption 
* Identifier
* JSON Web Token
* SMTP With Template Processor
* Payment Gateway (On Progress)
* Whatsapp (On Progress)
* Firebase (On Progress)
* User Management With Table Property Checker
* Middleware

# Basic Usage
## Step 1 : Installation
first add go-infrast package to your project, by using this command :
```
go get github.com/smokers10/go-infrast
```
## Step 2 : Configuration
make YAML file that contain configuration, here the example of configuration file you should make :
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
### Step 3 : Call Go Infrast!
here the code example to start using go-infrast : 
```
package main

import (
	"github.com/gofiber/fiber/v2"
	infrast "github.com/smokers10/infrast/head"
)

func main() {
	app := fiber.New()
	infrast, err := infrast.Head().Initialize("configuration.yaml")
	if err != nil {
		panic(err)
	}

	configuration := infrast.Configuration

	app.Listen(configuration.Application.Port)
}

```
# User Management & Middleware
## Step 1 : Configuration
To use user management & middleware you should add more configuration to your YAML file, here the configuration : 
```
user_management :
  user_credential : [
    {
      type : "ADMIN",
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
    email_template_path : "template/new-device-warning.html"
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
as you can see from yaml above you should have following table on your system <br>
1. User Table
2. Login Table
3. Registration Table
4. User Device Table
5. Reset Password Table

note : on each table you also need to define required property.
## Step 2 : Call User Management Or Middleware
```
package main

import (
	"github.com/gofiber/fiber/v2"
	infrast "github.com/smokers10/infrast/head"
)

func main() {
	app := fiber.New()
	infrast, err := infrast.Head().Initialize("configuration.yaml")
	if err != nil {
		panic(err)
	}

	configuration := infrast.Configuration

  // call middleware
  infrast.Middleware("user type") // <-- this must equal to user_credential.type other wise it will return error

  // call user management
 infrast.UserManagement("user type") // <-- this must equal to user_credential.type other wise it will return error

	app.Listen(configuration.Application.Port)
}

