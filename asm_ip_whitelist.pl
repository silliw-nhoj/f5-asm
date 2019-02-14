#!/usr/bin/perl
# asm_ip_whitelist.pl
# j.willis@f5.com - 11-2-2015
#
# Note: This script is provided as-is and is not supported by F5 Networks.
#
# Usage: You can view IP Address Exceptions by Policy and toggle them to either bypass or block.
#
#	Show: view IP address exceptions by policy.
#		./asm_ip_whitelist.pl <bigip-mgmt-address>
#
#	Toggle bypass or block: will toggle all or specified IP address exceptions to either bypass or block if they contain the description string specified.
#		./asm_ip_whitelist.pl <bigip-mgmt-address> <bypass | block> <description string> <ip-address optional>
#
#	Add White List IP Address: add a white list IP address to all policies. Note: description must contain a description string inorder to be affected by this script.
#		./asm_ip_whitelist.pl <bigip-mgmt-address> add <whitlist-IP> <IP-mask> <description>
#
#	Delete White List IP Address: delete a white list IP address from all policies.
#		./asm_ip_whitelist.pl <bigip-mgmt-address> delete <whitlist-IP>
#
#	Add White List host IP Addresses by file: parse a file of /32 IPs and add to all policies. Note: description must contain description string inorder to be affected by this script.
#		./asm_ip_whitelist.pl <bigip-mgmt-address> addfile </path/file> <description>
#
#	Delete White List IP Addresses by file: parse a file of /32 IPs and delete from all policies.
#		./asm_ip_whitelist.pl <bigip-mgmt-address> delfile </path/file>

use strict;
use warnings;

my ($bigip,$user,$password,$policy,$polid,$wListIPid,$whiteListIP,$wListIP,$wListIPMask,$wLIPDescription,$action,$bypassValue,$ipFile,$ipFileFH,$ipString);
my @whiteListIPIDs = ();
my @whiteListIPDetail = ();
my @policies = ();
my %policies = ();

##### Main ##########

&parseARGS;
&getCreds;
&getPolicies;
&getWhiteListIPs;
&showInfo;
if ($action) {
	if (($action eq "bypass") || ($action eq "block" )) {
		&toggleScannerIPs;
	} elsif (($action eq "add") || ($action eq "delete") || ($action eq "addfile") || ($action eq "delfile")) {
		&addorDeleteIP;
	} else {
		print "\nUnrecognized Action: $action";
		&usageMsg;
		exit;
	}

	&applyPolicy;
	# clear the policies hash so we can pull new info from the asm
	%policies = ();
	print "\n## AFTER #####\n\n";
	&getPolicies;
	&getWhiteListIPs;
	&showInfo;
}

##### Subroutines #######

sub parseARGS {
    if ($#ARGV >= 0) {  
		if ( $ARGV[0] =~ /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/ ) {
			$bigip = $ARGV[0];
			if ($ARGV[1]) {
				$action = $ARGV[1];	
			}
		} else {
			&usageMsg;
			exit;
		}
	} else {
	&usageMsg;
	exit;
	}
}

sub getPolicies {
	@policies = `curl -k -u $user:$password -X GET https://$bigip/mgmt/tm/asm/policies/ 2>/dev/null | awk ' BEGIN {RS=","}; {print}'`;
	foreach (@policies) {
		chomp $_;
		if (/^\"id\":\"(.*)\"/) {
			$polid = $1;
			my @policy =  `curl -k -u $user:$password -X GET https://$bigip/mgmt/tm/asm/policies/$polid 2>/dev/null | awk ' BEGIN {RS=","}; {print}'`;
			foreach (@policy) {
				if (/^\"name\":\"(.*)\"/) {
					$policy = $1;
					$policies{$policy}{id} = $polid;
				}
			}		
		}
		if (/^\"name\":\"(.*)\"/) {
			$policy = $1;
			$policies{$policy}{id} = $polid;
		}
	}
	
}

sub getWhiteListIPs {
	foreach $policy (sort keys %policies) {
		@whiteListIPIDs = `curl -k -u $user:$password -X GET https://$bigip/mgmt/tm/asm/policies/$policies{$policy}{id}/whitelist-ips 2>/dev/null | awk ' BEGIN {RS=","};{print}'`;
		foreach (@whiteListIPIDs) {
			chomp $_;
			if (/\"id\":\"(.*)\"/) {
				$wListIPid = $1;
				$policies{$policy}{whiteListIPs}{$wListIPid}{id} = $wListIPid;
				$policies{$policy}{hasWLIP} = 1;
			}
		}
		
		foreach $wListIPid (sort keys %{$policies{$policy}{whiteListIPs}}){
			my ($block,$learn,$log,$ignore);

			@whiteListIPDetail = `curl -k -u $user:$password -X GET https://$bigip/mgmt/tm/asm/policies/$policies{$policy}{id}/whitelist-ips/$policies{$policy}{whiteListIPs}{$wListIPid}{id} 2>/dev/null | awk ' BEGIN {RS=","};{print}'`;
			foreach (@whiteListIPDetail) {
				if (/"ipAddress\":\"(.*)\"/) {
					$policies{$policy}{whiteListIPs}{$wListIPid}{ip} = $1;
				}
				if (/"description\":\"(.*)\"/) {
					$policies{$policy}{whiteListIPs}{$wListIPid}{description} = $1;
				}
				if (/"neverLearnRequests\":(.*)/) {
					$learn = $1;
					$policies{$policy}{whiteListIPs}{$wListIPid}{neverLearn} = $learn;
				}

				if (/"(?:neverBlockRequests|blockRequests)\":(.*)/) {
					$block = $1;
					$policies{$policy}{whiteListIPs}{$wListIPid}{neverBlock} = $block;
				}
				
				
				if (/"neverLogRequests\":(.*)/) {
					$log = $1;
					$policies{$policy}{whiteListIPs}{$wListIPid}{neverLog} = $log;
				}
				

				if (/"ignoreAnomalies\":(.*)/) {
					$ignore = $1;
					$policies{$policy}{whiteListIPs}{$wListIPid}{ignoreAnomalies} = $ignore;
				}
				
			}
			if (!defined($learn)) {
				$policies{$policy}{whiteListIPs}{$wListIPid}{neverLearn} = "undefined";
			}
			if (!defined($block)) {
				$policies{$policy}{whiteListIPs}{$wListIPid}{neverBlock} = "undefined";
			}
			if (!defined($log)) {
				$policies{$policy}{whiteListIPs}{$wListIPid}{neverLog} = "undefined";
			}
			if (!defined($ignore)) {
				$policies{$policy}{whiteListIPs}{$wListIPid}{ignoreAnomalies} = "undefined";
			}
		}
	}
}

sub getCreds {
    print "\nUsername: "; 
    chomp($user=<STDIN>);
    print "Password: ";
    system('stty','-echo');
    chomp($password=<STDIN>);
    system('stty','echo');
    my $test = `curl -k -u $user:$password -X GET https://$bigip/mgmt/tm/ltm/virtual 2>/dev/null`;
    if ($test =~ /Authentication required/) {
		print "**Failed Auth**\n";
		exit;
    }
	print "\n";
    
}

sub usageMsg {
    print "# Note: This script is provided as-is and is not supported by F5 Networks.\n# Usage: You can view IP Address Exceptions by Policy and toggle them to either bypass or block\n\n";
	print "\tShow: view IP address exceptions by policy\n\t\t./asm_ip_whitelist.pl <bigip-mgmt-address>\n";
	print "\tToggle bypass or block: will toggle all or specified IP address exceptions to either bypass or block if they contain the defined description string.\n\t\t./asm_ip_whitelist.pl <bigip-mgmt-address> <bypass | block> <description string> <ip-address optional>\n";
	print "\tAdd White List IP Address: add a white list IP address to all policies. Note: description must contain a description string inorder to be affected by this script.\n\t\t./asm_ip_whitelist.pl <bigip-mgmt-address> add <whitlist-IP> <IP-mask> <description>\n";
	print "\tDelete White List IP Address: delete a white list IP address from all policies.\n\t\t./asm_ip_whitelist.pl <bigip-mgmt-address> delete <whitlist-IP>\n";
	print "\tAdd White List host IP Addresses by file: parse a file of /32 IPs and add to all policies. Note: description must contain a description string inorder to be affected by this script.\n\t\t./asm_ip_whitelist.pl <bigip-mgmt-address> addfile </path/file> <description>\n";	
	print "\tDelete White List IP Addresses by file: parse a file of /32 IPs and delete from all policies.\n\t\t./asm_ip_whitelist.pl <bigip-mgmt-address> delfile </path/file>\n";

    exit;
}

sub uniq {
    my %seen;
    return grep {!$seen{$_}++ } @_;
}

sub showInfo {
	foreach $policy (sort keys %policies) {
		next if (!($policies{$policy}{hasWLIP}));
		print "Policy: $policy - ID: $policies{$policy}{id}\n";
		foreach $wListIPid (sort keys %{$policies{$policy}{whiteListIPs}}){
			print "\tWhite List IP: $policies{$policy}{whiteListIPs}{$wListIPid}{ip} - Description: $policies{$policy}{whiteListIPs}{$wListIPid}{description} - ID: $wListIPid\n";
			print "\t\tNever Block Requests: $policies{$policy}{whiteListIPs}{$wListIPid}{neverBlock}\n";
			print "\t\tNever Learn Requests: $policies{$policy}{whiteListIPs}{$wListIPid}{neverLearn}\n";
			print "\t\tNever Log Requests: $policies{$policy}{whiteListIPs}{$wListIPid}{neverLog}\n";
			print "\t\tIgnore Anomalies: $policies{$policy}{whiteListIPs}{$wListIPid}{ignoreAnomalies}\n";
		}
		print "\n";
	}
}

sub toggleScannerIPs {
	if ($#ARGV >= 2) {
		if ($ARGV[2]) {
			$ipString = $ARGV[2];
		}
		if ($ARGV[3]) {
			$wListIP = $ARGV[3];
		}
	} else {
		&usageMsg;
		exit;
	}


	if ($action eq "bypass") {
		$bypassValue = "true"; 
	} elsif ($action eq "block") {
		$bypassValue = "false";
	}

	foreach $policy (sort keys %policies) {
		if ($policies{$policy}{whiteListIPs}) {
			foreach $wListIPid (sort keys %{$policies{$policy}{whiteListIPs}}){
				next if ($policies{$policy}{whiteListIPs}{$wListIPid}{description} !~ "$ipString");
				if ($wListIP) {
					if ($wListIP eq $policies{$policy}{whiteListIPs}{$wListIPid}{ip}) {
						my $blackhole = `curl -k -u $user:$password -H "Content-Type: application/json" -X PATCH -d '{"neverBlockRequests":$bypassValue,"neverLearnRequests":$bypassValue,"neverLogRequests":$bypassValue,"ignoreAnomalies":$bypassValue}' https://$bigip/mgmt/tm/asm/policies/$policies{$policy}{id}/whitelist-ips/$policies{$policy}{whiteListIPs}{$wListIPid}{id} 2>/dev/null`;
						$policies{$policy}{changed} = 1;
					}
					
				} else {
					my $blackhole = `curl -k -u $user:$password -H "Content-Type: application/json" -X PATCH -d '{"neverBlockRequests":$bypassValue,"neverLearnRequests":$bypassValue,"neverLogRequests":$bypassValue,"ignoreAnomalies":$bypassValue}' https://$bigip/mgmt/tm/asm/policies/$policies{$policy}{id}/whitelist-ips/$policies{$policy}{whiteListIPs}{$wListIPid}{id} 2>/dev/null`;
					$policies{$policy}{changed} = 1;
				}
			}
		}
	}
}

sub addorDeleteIP {
	if ($action eq "add") {
		if ($#ARGV >= 4) {
				$wListIP = $ARGV[2];
				$wListIPMask = $ARGV[3];
				$wLIPDescription = $ARGV[4];
		} else {
			&usageMsg;
			exit;
		}
		foreach $policy (sort keys %policies) {
			my $blackhole = `curl -k -u $user:$password -H "Content-Type: application/json" -X POST -d '{"ipAddress":"$wListIP","description":"$wLIPDescription","ipMask":"$wListIPMask"}' https://$bigip/mgmt/tm/asm/policies/$policies{$policy}{id}/whitelist-ips/ 2>/dev/null`;
			$policies{$policy}{changed} = 1;
		}
	}
	
	if ($action eq "delete") {
		if ($#ARGV >= 2) {
				$wListIP = $ARGV[2];
		} else {
			&usageMsg;
			exit;
		}
		foreach $policy (sort keys %policies) {
			foreach $wListIPid (sort keys %{$policies{$policy}{whiteListIPs}}){
				if ($wListIP eq $policies{$policy}{whiteListIPs}{$wListIPid}{ip}) {
					my $blackhole = `curl -k -u $user:$password -H "Content-Type: application/json" -X DELETE https://$bigip/mgmt/tm/asm/policies/$policies{$policy}{id}/whitelist-ips/$wListIPid 2>/dev/null`;
					$policies{$policy}{changed} = 1;
				}
			}
		}
	}

	if ($action eq "addfile") {
		$wListIPMask = "255.255.255.255";

		if ($#ARGV >= 3) {
				$ipFile = $ARGV[2];
				$wLIPDescription = $ARGV[3];
		} else {
			&usageMsg;
			exit;
		}

		open($ipFileFH, "$ipFile") || die "Unable to open '$ipFile': $!\n";

		while ( my $ip = <$ipFileFH>) {
            chomp($ip);
            $ip =~ s/[\r\n]$//;
            $ip =~ s/\s+/ /g;
            $ip =~ s/\s+$//;
			foreach $policy (sort keys %policies) {
				my $blackhole = `curl -k -u $user:$password -H "Content-Type: application/json" -X POST -d '{"ipAddress":"$ip","description":"$wLIPDescription","ipMask":"$wListIPMask"}' https://$bigip/mgmt/tm/asm/policies/$policies{$policy}{id}/whitelist-ips/ 2>/dev/null`;
				$policies{$policy}{changed} = 1;
			}

		}

	}
	if ($action eq "delfile") {

		if ($#ARGV >= 2) {
				$ipFile = $ARGV[2];
		} else {
			&usageMsg;
			exit;
		}

		open($ipFileFH, "$ipFile") || die "Unable to open '$ipFile': $!\n";

		while ( my $ip = <$ipFileFH>) {
            chomp($ip);
            $ip =~ s/[\r\n]$//;
            $ip =~ s/\s+/ /g;
            $ip =~ s/\s+$//;
			foreach $policy (sort keys %policies) {
				foreach $wListIPid (sort keys %{$policies{$policy}{whiteListIPs}}){
					if ($ip eq $policies{$policy}{whiteListIPs}{$wListIPid}{ip}) {
						my $blackhole = `curl -k -u $user:$password -H "Content-Type: application/json" -X DELETE https://$bigip/mgmt/tm/asm/policies/$policies{$policy}{id}/whitelist-ips/$wListIPid 2>/dev/null`;
						$policies{$policy}{changed} = 1;
					}
				}
			}
		}
	}
}

sub applyPolicy {
	foreach $policy (sort keys %policies) {
		if ($policies{$policy}{changed}) {
			my $blackhole = `curl -k -u $user:$password -H "Content-Type: application/json" -X POST -d '{"policyReference": {"link":"https://localhost/mgmt/tm/asm/policies/$policies{$policy}{id}"}}' https://$bigip/mgmt/tm/asm/tasks/apply-policy/ 2>/dev/null`;
			print "\t** Applying policy to $policy\n";
		}
	}
}