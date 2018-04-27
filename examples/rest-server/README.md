**Introduction**
----
  REST API contains easy to use interface to the LwM2M server and client communication.
  
  Detailed [REST API documentation](./RESTAPI.md).

**Building**
----
1. Install tools and libraries required for project building for Debian based distributions (Debian, Ubuntu):
```
$ sudo apt-get install -y git cmake build-essential
$ sudo apt-get install -y libmicrohttpd-dev libjansson-dev libcurl4-gnutls-dev libb64-dev
```
2. Install required libraries from Github:
```
$ git clone https://github.com/babelouest/ulfius.git
$ cd ulfius/
$ git submodule update --init
$ cd lib/orcania
$ make && sudo make install
$ cd ../yder
$ make && sudo make install
$ cd ../..
$ make
$ sudo make install
```
3. Build LwM2M-REST server
```
$ git clone https://github.com/8devices/wakaama.git
$ cd wakaama/
$ mkdir build
$ cd build/
$ cmake ../examples/rest-server
$ make
```
After third step you should have binary file called `restserver` in your `wakaama/build/` directory.

**Usage**
----
You can get some details about `restserver` by using `--help` or `-?` argument:
```
wakaama/build $ ./restserver --usage
Usage: restserver [OPTION...]
Restserver - interface to LwM2M server and all clients connected to it

  -c, --config=FILE          Specify parameters configuration file
  -l, --log=LOGGING_LEVEL    Specify logging level (0-5)
  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```

You can get some details about `restserver` usage by using `--usage` argument:
```
wakaama/build $ ./restserver --usage
Usage: restserver [-?V] [-c FILE] [-l LOGGING_LEVEL] [--config=FILE]
            [--log=LOGGING_LEVEL] [--help] [--usage] [--version]
```

**Arguments list:**
- `-c CONFIG_FILE` and `--config CONFIG_FILE` is used to load config file.

     Example of configuration file:
     
```
    {
      "http": {
        "port": 8888,
      },
      "coap": {
        "port": 5555,
      },
      "logging": {
        "level": 5
      }
    }
```
    
- `-l LOGGING_LEVEL` and `--log LOGGING_LEVEL` specify logging level from 0 to 5:

    `0: FATAL` - only very important messages are printed to console (usually the ones that inform about program malfunction).
    
    `1: ERROR` - important messages are printed to console (usually the ones that inform about service malfunction).
    
    `2: WARN` - warnings about possible malfunctions are reported.
    
    `3: INFO` - information about service actions (e.g., registration of new clients).
    
    `4: DEBUG` - more detailed information about service actions (e.g., detailed information about new clients).
    
    `5: TRACE` - very detailed information about program actions, including code tracing.
    
- `-V` and `--version` - print program version.
