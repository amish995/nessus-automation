# nessus-automation
Simple scripts to take the Nessus CSV exports for plugins 21643 and 70657 and generate clean tables for all the weak SSL ciphers and SSH ciphers supported on the hosts.

##Usage
```python nessus_parse.py -i <nessus_ssl.csv>```
```python nessus_ssh.py -i <nessus_ssh.csv>```

The nessus CSV files must be generated as CSV reports with only the outputs for the respective plugins, with just the `Host`, `Port`, `Protocol` and `Plugin Output` columns enabled.

##To-do
- Merge both functions into one script
- Ability to parse from full Nessus CSV
