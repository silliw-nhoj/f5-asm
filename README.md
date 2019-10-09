# asm_ip_whitelist.pl
## Note: This script is provided as-is and is not supported by F5 Networks.

## Usage: You can view IP Address Exceptions by Policy and toggle them to either bypass or block.

       Show: view IP address exceptions by policy.
               ./asm_ip_whitelist.pl <bigip-mgmt-address>

       Toggle bypass or block: will toggle all or specified IP address exceptions to either bypass or block if they contain the description string specified.
               ./asm_ip_whitelist.pl <bigip-mgmt-address> <bypass | block> <description string> <ip-address optional>

       Add White List IP Address: add a white list IP address to all policies. Note: description must contain a description string inorder to be affected by this script.
               ./asm_ip_whitelist.pl <bigip-mgmt-address> add <whitlist-IP> <IP-mask> <description>

       Delete White List IP Address: delete a white list IP address from all policies.
               ./asm_ip_whitelist.pl <bigip-mgmt-address> delete <whitlist-IP>

       Add White List host IP Addresses by file: parse a file of /32 IPs and add to all policies. Note: description must contain description string inorder to be affected by this script.
               ./asm_ip_whitelist.pl <bigip-mgmt-address> addfile </path/file> <description>

       Delete White List IP Addresses by file: parse a file of /32 IPs and delete from all policies.
               ./asm_ip_whitelist.pl <bigip-mgmt-address> delfile </path/file>

tested on versions 11.6 and 12
