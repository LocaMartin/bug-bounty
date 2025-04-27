
<hr>

<details>
<summary>Asset Table</summary>

| Category | Asset Type rOne |   Examples |
|---|---|---|
| Web Applications | URL, Domain, Wildcard | https://app.example.com, *.example.com    |
| Mobile Applications | Android: .apk, Android: PlayStore iOS: .ipa, iOS: App Store, iOS: Testflight | app-release.apk, com.example.app |
| APIs & Microservices | URL | https://api.example.com/v1/users     |
| Network & Infrastructure | CIDR, IP Address | 192.168.0.0/24, 203.0.113.5     |
| Executable / Desktop Apps | Executable, Windows: Microsoft Store | installer.exe, MyApp.appxbundle |
| Hardware / IoT Devices | Hardware/IoT | DeviceModel1234, thermostat.local     |
| Source Code Repositories | Source Code | GitHub repo URL, .git |      |
| Smart Contracts (Web3) | Smart Contract | 0xAbC123… on Ethereum, Solana program ID |
| AI Models & Endpoints    | AI Model | LLM endpoint URL|
</details>

<hr>
<details>
<summary>Web App</summary>

All oneliner commands are covered in [cheet sheet](/CHEAT-SHEET.md) and [README](/README.md)


</details>
<hr>
<details>
<summary>Mobile App</summary>

```bash
# Android APK Static Recon
apktool d app-release.apk -o apk_out && grep -R "api_key\|secret" apk_out
```
```bash

unzip -p app.ipa Payload/*.app/* | strings | grep -Ei "api_key|password"
# iOS IPA Quick Strings
```
</details>
<hr>
<details>
<summary>APIs & Microservices</summary>

```bash
# Fetch a live list of endpoints from Swagger/OpenAPI and probe them:
curl -s https://api.example.com/openapi.json | jq -r '.paths|keys[]' | sed 's/^/https:\/\/api.example.com/' | httpx -silent -o api-alive.txt
```
</details>
<hr>
<details>
<summary>Network & Infrastructure</summary>

```bash
nmap -p80,443 192.168.0.0/24 -oG - | grep "/open/" | awk '{print $2}'
```
</details>
<hr>
<details>
<summary>Executable / Desktop Apps</summary>

```bash
# Extract strings from a Windows EXE and look for credentials
strings installer.exe | grep -Ei "password|token|secret"
```
</details>
<hr>
<details>
<summary>Hardware / IoT Devices</summary>

```bash
# Quickly discover local IoT hosts via mDNS and probe HTTP
avahi-browse -rt _http._tcp | grep host-name | awk '{print $4}' | xargs -I{} httpx -silent -title
```
</details>
<hr>
<details>
<summary>Source Code Repositories</summary>

```bash
# Clone and scan for hard-coded secrets with TruffleHog
git clone https://github.com/org/repo.git && trufflehog repo | tee secrets.log
```
</details>
<hr>
<details>
<summary>
Web3
</summary>

# Dynamic Tests
**Dynamic Front-End DAST**
> OWASP ZAP Quick Scan (Proxy Mode)
```bash
# Start ZAP in daemon mode; point your browser or automated crawler to use 127.0.0.1:8080 as proxy
docker run -u zap -p 8080:8080 owasp/zap2docker-stable zap.sh -daemon \
  -port 8080 -host 0.0.0.0 -config api.disablekey=true
```
```bash
# Runs ZAP’s spider plus active scanning against your DApp front end.
zap-cli quick-scan --self-contained --start-options '-config api.disablekey=true' \
  --spider-recurse --scanners all http://dapp.example.com
```
> Burp Suite Headless Scan

```bash
# Automates Burp’s crawl & scan suite headlessly.  ( works only wtih burp pro with)
burpsuite_pro --project-file=proj.burp --auto-save-state --logger-file burp.log \
  --headless-spider http://dapp.example.com --headless-scan
```
> JSON-RPC & GraphQL Fuzzing
JSON-RPC Method Enumeration & Fuzzing with Etheno
```bash
# Launch Etheno proxy that multiplexes to Infura & Alchemy
etheno --rpc-http https://mainnet.infura.io/v3/$KEY --rpc-http https://eth-mainnet.alchemyapi.io/v2/$KEY \
  --port 8545
# Then fuzz methods
wfuzz -c -z list,methods.txt --hc 400 --url http://localhost:8545/jsonrpc?jsonrpc=2.0&method=FUZZ&params=[]&id=1
# Where methods.txt lists common JSON-RPC methods (e.g. eth_sendTransaction, debug_traceTransaction
```
> GraphQL Introspection & Fuzzing for DApps
```bash
# Introspect schema
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name}}}}"}' \
  https://api.dapp.com/graphql | jq '.data.__schema'
# Fuzz each field
jq -r '.data.__schema.types[].fields[].name' schema.json \
  | while read f; do curl -s -X POST -H "Content-Type: application/json" \
      -d "{\"query\":\"{ $f }\"}" https://api.dapp.com/graphql; done
```
> On-Chain Dynamic Interaction
```bash 
# Etherscan ABI & Source Retrieval
curl -s "https://api.etherscan.io/api?module=contract&action=getabi&address=$ADDR&apikey=$KEY" \
  | jq -r .result > contract.abi.json
curl -s "https://api.etherscan.io/api?module=contract&action=getsourcecode&address=$ADDR&apikey=$KEY" \
  | jq .result[0].SourceCode > contract.sol
# Fetch live ABI and source to dynamically generate calls.
```
> On-Chain Recon & ABI Retrieval
```bash 
# Fetch verified source or ABI directly via Etherscan APIs:
curl "https://api.etherscan.io/api?module=contract&action=getabi&address=$ADDR&apikey=$KEY" \
  | jq -r .result
# Retrieves the ABI for a verified contract 
```
```bash
curl "https://api.etherscan.io/api?module=contract&action=getsourcecode&address=$ADDR&apikey=$KEY" \
  | jq .result
```

> RPC & Bytecode Inspection
```bash
# Quickly pull deployed bytecode via Web3 CLI
node -e "const Web3=require('web3');(async()=>{console.log(await new Web3('https://mainnet.infura.io/v3/$KEY').eth.getCode('$ADDR'))})();"
# Prints on-chain bytecode for manual pattern analysis 
```
> Symbolic Execution with Mythril
```bash
myth analyze contract.sol --rpc https://mainnet.infura.io/v3/$INFURA_KEY -o json
# Runs Mythril against contract.sol via Infura and outputs JSON 
# Invoke Mythril to symbolically analyze source or bytecode
```
> Event Log Extraction
```bash
curl "https://api.etherscan.io/api?module=logs&action=getLogs&fromBlock=0&toBlock=latest&address=$ADDR&topic0=$SIG&apikey=$KEY" \
  | jq .result 
# Grabs all matching event logs by signature
# Filter and extract event logs for on-chain behavior
```
> Mythril Live Analysis
```bash 
myth analyze /path/to/contract.sol --rpc http://localhost:8545 --json -o myth-output.json
# Symbolically executes against live node to reveal reentrancy and auth bugs
```
> RPC Method Support Check (EIP-7663)
```bash
# Check if node supports eth_blobBaseFee
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_checkMethodSupport","params":["eth_blobBaseFee"],"id":1}' \
  http://node.example.com:8545
# Identifies JSON-RPC support gaps in node providers
```
> Health & Metrics via cURL & Prometheus Endpoint
```bash
curl -s http://node.example.com:9545/metrics | grep -E 'go_memstats|http_metrics'
# Quickly checks health and Go runtime metrics on Geth or OpenEthereum nodes.
```
> Workflow-Driven Automation
```yml
# CI/CD DAST Job for Web3 Front-end
# .github/workflows/web3-dast.yml
on:
  schedule: [ { cron: '0 3 * * *' } ]
jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run ZAP Quick Scan
        run: zap-cli quick-scan --self-contained http://dapp.example.com
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: dast-report
          path: zap-report.html
```
> Property-Based Fuzzing in CI
```yaml
# .gitlab-ci.yml
test_fuzz:
  image: ruby:2.7
  script:
    - forge test --fork-url $RPC_URL --match MyContractFuzz
  only: [workflow_dispatch]
```

# Static Tests
```bash
slither . --print human-summary
# Prints a human-friendly summary of contract functions and dependencies 
```
```bash
slither . --list-detectors
# Lists all vulnerability detectors available 
```
```bash
slither . --print contract-summary
# Generates a high-level “floorplan” of your contract’s structure 
```
```bash
docker run --rm mythril/myth analyze --truffle
# Using the Docker image, analyze a Truffle project in place 
```
> Fuzzing with Echidna
```bash
# Property-based fuzzing to break invariants:
echidna-test contracts/ --contract MyToken --config echidna.yaml
# Fuzzes MyToken against invariants in echidna.yaml 
```
```bash
echidna-test contracts/ --contract Vault --init-cmd "deploy()" --poststate-cmd "balanceCheck()"
# Custom init & post-state commands for complex setups 
```
> Foundry Fuzz & Testing
```bash
forge test --match MyContractTest --fork-url $RPC_URL
# Runs only tests matching MyContractTest against a forked chain 
```
```bash
cast etherscan-source 0x1234...abcd
# Fetches and saves verified source from Etherscan via Foundry’s cast
```

</details>

<hr>
<details>
<summary>AI Models & Endpoints</summary>

```bash
# Fuzz an LLM endpoint for prompt‐injection via common vectors:
echo '{"prompt":"1; system(\"id\");"}' | jq -c . | while read p; do curl -s -X POST -H "Content-Type: application/json" -d "$p" https://ai.example.com/generate; done
```
</details>
<hr>