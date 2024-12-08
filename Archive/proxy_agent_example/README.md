# LLMProxy Example Code ProxyAgent

This folder contains example code (written in both C and Python) that demonstrates how to dispatch requests to `LLMProxy` via `ProxyAgent` while using a RESTful API.
The main benefit of this approach is to bypass the 29sec timeout that directly sending the request to `LLMProxy` will encounter.
The examples work very similar to the ones in `rest_example/`.
The major difference being the use of the `ProxyAgent` process.

---

## Getting Started

#### Setup
1. Install Python 3.x and required dependencies by running the setup script:
    ```
    bash setup.sh
    ```

#### Configuring and Running `ProxyAgent`
The `ProxyAgent` uses `config.json` to read the access key, port and interface to run on. Please modify these fields accordingly

1. Add your access key to `config.json` (line 4)
2. You can optionally configure the port and address on which the `ProxyAgent` process will run. Specifying `0.0.0.0` as the address will force the `ProxyAgent` to listen on all interfaces
3. Run `ProxyAgent` by executing `python3 ProxyAgent.py`

### Running the C Example
1. Use the `Makefile` to compile the program:
    ```
    make clean
    make
    ```
2. Run the executable, specifying the address and port number on which `ProxyAgent` is running:
    ```
    ./example <proxy-agent-address> <proxy-agent-port>
    ```
---

### Running the Python Example
1. Execute the example Python script, specifying the address and port number on which `ProxyAgent` is running:
    ```
    python3 example.py <proxy-agent-address> <proxy-agent-port>
    ```
---