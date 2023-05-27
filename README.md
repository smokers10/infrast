# go-infrastructure
A simpler way to setup your infrastructure for your golang project!

## How To Access Every Infrastructure?
you can access every provided infrastructure by calling its function directly or use head function to access all infrastructure in singe function call, here step-by-step to use head function :
* Make configuration YAML (follow the prefered vonfiguration format below).
* Call head function on your project it will require configuration YAML file path.

## Prefered Configuration Format
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

## How About Unit Testing ?
i made mock contract on every infrastructure except databases but you need to use Testify package to make it work, just in case you does'nt add Testify package you can run command provided below :

```
$ go get https://github.com/stretchr/testify
```
if you have Testify on your project it's good to go! see code example below to conduct mock testing on your project :

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
