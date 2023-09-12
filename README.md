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


