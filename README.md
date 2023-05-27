# go-infrastructure
simpler way to setup your infrastructure for golang such as database, encryption, jwt and others

## How To Access Every Mini Module?
you only need access it using "head" but there some preparation you need to be done, here the step :

* Make configuration YAML you can see format below
* Call head function set parameter with your configuration directory path
* You good to go! enjoy the simplecity of go :)

## Configuration YAML Example
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
i already made some mock contract on every mini module but you need to use Testify package to make it work, just in case you doesnt add Testify module you can run command bellow :

```
$ go get https://github.com/stretchr/testify
```
if you have Testify on your project it good to go! see code example to mock testing your project :

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