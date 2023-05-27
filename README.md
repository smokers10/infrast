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