# GO INFRAST!
A simpler way to setup infrastructure for your golang project!

# Provided Module
here the module we provided for your project :
* Database (Postgre & Mongo) support multi instance
* Encryption (AES & Bcrypt)
* Identifier 
* JSON Web Token
* SMTP With Template Processor
* Payment Gateway (Midtrans)
* Whatsapp (Twillio)
* Firebase
* User Management (3-step-registration)
* Middleware (Proccess only)

# How To Use
## Step 1: Installation
first add go-infrast package to your project, by using this command :
```
go get github.com/smokers10/go-infrast
```
## Step 2: Configuration
here the example of configuration file you can follow :
```
application :
  port: :8000
  secret: your-encrypted-secret
  user_management_pg_instance: user-management # which postgresql instance used for user management
postgres : [
  {
    label: general,
    host: localhost,
    port: 5432,
    user: testuser,
    password: testpass,
    db_name: testdb,
    max_open_connections: 1,
    max_idle_connections: 2,
    connection_max_life_time: 2,
  },
  {
    label: user-management,
    host: localhost,
    port: 5433,
    user: infrast_um,
    password: infrastumpass,
    db_name: infrastdbum,
    max_open_connections: 1,
    max_idle_connections: 2,
    connection_max_life_time: 2,
  },
]
mongodb : [
  {
    label : "dummy1",
    uri : localhost/bla-bla-bla,
    max_pool : 10,
    min_pool : 5,
    max_idle_connections : 2,
    db_name : testdb,
  },
  {
    label : "dummy2",
    uri : localhost/bla-bla-bla,
    max_pool : 10,
    min_pool : 5,
    max_idle_connections : 2,
    db_name : testdb,
  },
]
smtp: 
  host: localhost
  password: your-encrypted-smtp-password
  username: testuser
  port: 5432
  sender: sender
midtrans :
  server_key: your-encrypted-midtrans-server-key
  iris_key: your-encrypted-midtrans-iris-key
  enabled_payments: 
    - bca-klik
    - bri
    - gopay
whatsapp :
  sid: wa-sid
  auth_token: encrypted-auth-token
  sender: +628<...>
firebase: 
  service_account_key: your-encrypted-service-account-key
```

<b> WARNING </b>
Some configuration value need to be encrypted such us:
- Application secret
- PostgreSQL password
- MongoDB URI
- SMTP password
- Midtrans server key
- Midtrans iris key
- Whatsapp auth token
- Firebase service account key

if you set mentioned config value with plain text it will give you error message, due to how we implement encryption on this package please use our provided tool [enigma](https://github.com/smokers10/enigma) for creating confidential configuration value.

<b> How To Setup Firebase </b> <br>
As you can see the firebase configuration required firebase service account key, to get key please follow this instruction

1. Go to your firebase console then go to `project setting`.
2. Select `service account` tab.
3. On `firebase admin SDK` click `Generate new private key` button, it will show you modal pop up click `Generate Key` you will download a JSON file from firebase console.
4. After you downloaded the JSON, open the file and then encode all information inside using base64, you can use [this](https://www.base64decode.org/) site to encode your private key.
5. encrypt your encoded private key using [enigma](https://github.com/smokers10/enigma).
6. Set encrypted private key to your configuration YAML.

### Step 3: Initialize Infrast
here the code example on how to use infrast with fiber framework: 
```
package main

import (
	"github.com/gofiber/fiber/v2"
	infrast "github.com/smokers10/infrast/head"
)

func main() {
    app := fiber.New()
    key := os.GetEnv("aes-key-env-name")

	infrast, err := infrast.Head("infrast_configuration.yaml", key)
	if err != nil {
		panic(err)
	}

	configuration := infrast.Configuration

	app.Listen(configuration.Application.Port)
}

```
<b>Note</b> you can make your own AES key based on [this](https://pkg.go.dev/crypto/aes#pkg-variables) documentation or use auto generated key by [enigma](https://github.com/smokers10/enigma)

# User Management & Middleware
## Step 1: Configuration
To use user management & middleware you should add more configuration to your YAML file and make sure you mark which postgres instace used for user management, here the configuration: 
```
user_management :
  message_template: 
    new_registration_email_template_path: template/new-registration.html
    new_device_warning_email_template_path: template/new-device.html
    forgot_password_email_template_path: template/forgot-passwrod.html
    new_registration_message_template: your registration otp is %v please don't share to anybody
    new_device_warning_message_template: you logged on another device klick URL bellow to log out %v
    forgot_password_message_template: your reset password otp is %v please don't share to anybody
    login_cancelation_url: http://localhost:8000/cancel-login/%s #require 1 parameter to place device id
  users: [
    {
      type: ADMIN,
      user_table: admins,
      credential: [username, email],
      id_property: id,
      photo_profile_property: profile,
      password_property: password,
      username_property: username,
      email_property: email,
      phone_property: phone
    },
    {
      type: customer,
      user_table: customers,
      credential: [username, email, phone],
      id_property: id,
      photo_profile_property: profile,
      password_property: password,
      username_property: username,
      email_property: email,
      phone_property: phone
    },
  ]
  login: 
    table_name: login
    token_property: token
    failed_counter_property: failed_attempt
    type_property: user_type
    credential_property: credential
    login_at_property: login_at
    device_id_property: device_id
    attempt_at_property: attempt_at
    max_failed_attempt: 3
    login_block_duration: 300
  user_device: 
    table_name: user_devices
    id_property: id
    device_id_property: device_id
    user_id_property: user_id
    user_type_property: user_type
  registration: 
    table_name: registration
    id_property: id
    credential_property: credential
    token_property: token
    otp_property: otp
    registration_status_property: status
    device_id_property: device_id
    created_at_property: created_at
    user_type_property: user_type
    fcm_token_property: fcm_token
  reset_password: 
    table_name: reset_password
    id_property: id
    token_property: token
    otp_property: otp
    credential_property: credential
    created_at_property: created_at
    validity_duration: 900000
    user_type_property: user_type
  user_fcm_token :
    table_name: user_fcm
    id_property: id
    token_property: token
    timestamp_property: timestamp
    user_type_property: user_type
    user_id_property: user_id

```
as you can see from yaml above you should have following table on your system <br>
1. User Table
2. Login Table
3. Registration Table
4. User Device Table
5. Reset Password Table
6. User FCM Token Table

note: on each table you need to define required property infrast will detect your table structure to check if you define required table property.
## Step 2: Call User Management Or Middleware
```
package main

import (
	"github.com/gofiber/fiber/v2"
	infrast "github.com/smokers10/infrast/head"
)

func main() {
	app := fiber.New()
	infrast, err := infrast.Head("your-yaml-path", "your-aes-key")
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
```
## Message Template Explanation
As you can see infrast configuration on user management there is a `message_template`, this configuration is used to make infrast detect email and WA message template on you sistem
so infrast can send notification to user when some condition occured such us registration verification, forgot password and new device login notification. Here de detailed explanation on each configuration: 
<table>
  <tr>
    <th>Configuration Name</th>
    <th>Description</th>
    <th>Required Data On Template</th>
  </tr>
  <tr>
    <td>new_registration_email_template_path</td>
    <td>email HTML template file path that used when verificating new user registratio</td>
    <td>
      {{.otp}}
    </td>
  </tr>
  <tr>
    <td>new_device_warning_email_template_path</td>
    <td>email HTML template file path that use when user login with unregistered device</td>
    <td>
      {{.logout_url}} <br>
      {{.logged_at}}
    </td>
  </tr>
  <tr>
    <td>forgot_password_email_template_path</td>
    <td>email HTML template file path that used when user forgot their password</td>
    <td>
      {{.issuer_name}} <br>
      {{.otp}}
    </td>
  </tr>
  <tr>
    <td>new_registration_message_template</td>
    <td>message template to sent when user verificating new user registration via WA</td>
    <td>single %v to concenate otp</td>
  </tr>
  <tr>
    <td>new_device_warning_message_template</td>
    <td>message template to sent when user login unregistered device</td>
    <td>single %v to concenate logout URL</td>
  </tr>
    <tr>
    <td>forgot_password_message_template</td>
    <td>message tamplate to sent when user forgot their password and prefered to send reset code via WA </td>
    <td>single %v to concenate reset password code</td>
  </tr>
</table>

# Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch
3. Commit your Changes 
4. Push to the Branch
5. Open a Pull Request

# Acknowledgments & Depedencies
The following packages were used in this project :
- golang jwt - [Repository / Package Page](github.com/golang-jwt/jwt/v5)
- goolang uuid - [Repository / Package Page](github.com/google/uuid)
- lib pq - [Repository / Package Page](github.com/lib/pq)
- nyaruka phonenumbers - [Repository / Package Page](github.com/nyaruka/phonenumbers )
- stretchr testify - [Repository / Package Page](github.com/stretchr/testify)
- gotp - [Repository / Package Page](github.com/xlzd/gotp)
- mongo driver - [Repository / Package Page](go.mongodb.org/mongo-driver)
- crypto - [Repository / Package Page](golang.org/x/crypto)
- yaml - [Repository / Package Page](gopkg.in/yaml.v3)
- midtrans go - [Repository / Package Page](github.com/midtrans/midtrans-go)
- twillio go - [Repository / Package Page](github.com/twilio/twilio-go)
- firebase - [Repository / Package Page](firebase.google.com/go)
- and many more

# Author & Contributor

Nadzar Mutaqin - [instagram](https://www.instagram.com/vermillione666/) - [linkedin](https://www.linkedin.com/in/nadzar-mutaqin-178a8b153/) - nadzarmutaqin4@gmail.com

<p><a href="#readme-top">back to top</a></p>


