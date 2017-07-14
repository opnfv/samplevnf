#!/usr/bin/perl

##
## Copyright (c) 2010-2017 Intel Corporation
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

=head1 NAME

ipv6_tun_bindings.pl

=head1 SYNOPSIS

 ipv6_tun_bindings.pl [-n <num_entries>] [-tun_ip <ipv6>] [-mac <next_hop_mac>] 
                      [-pub_ip <ipv4>] [-port <begin>-<end>] [-set <num_ports>]
                      [-suffix <suffix>] [-test <num_entries>] [-sym|-nosym]
                      [-help]

=head1 DESCRIPTION

This script can be used to generate a binding table for the IPv6 Tunnel
task implemented in PROX (ipv6_encap and ipv6_decap).
The entries in this table bind a specific tunnel endpoint (lwB4 in lw4over6
architecture) to a public IPv4 address and port set.
The port set is actually derived from the port specified in the table
and a port bitmask in the PROX task configuration ("lookup port mask").

The ipv6_encap task uses the binding table to know where to tunnel IPv4
traffic to. The ipv6_decap task uses the table to verify tunnel packets
have a valid public IPv4 and port combination for the originating tunnel.   

The table uses the Lua syntax so it can be loaded into PROX. Example:
return {
   {ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0000"), mac = mac("fe:80:00:00:00:00"), ip = ip("171.205.239.1"), port = 4608},
   {ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0001"), mac = mac("fe:80:00:00:00:00"), ip = ip("171.205.239.1"), port = 4672},
   {ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0002"), mac = mac("fe:80:00:00:00:00"), ip = ip("171.205.239.1"), port = 4736},
   {ip6 = ip6("fe80:0000:0000:0000:0200:00ff:fe00:0003"), mac = mac("fe:80:00:00:00:00"), ip = ip("171.205.239.1"), port = 4800},
}

The script generates consecutive entries, starting from a given IP address
and assigning ports within a given range, increasing the port number by a
fixed amount which should correspond to the port lookup mask being used.

UDF table: In addition to the binding table itself, the script can optionally
generate accompanying UDF tables for generating test traffic matching the
binding table. Such UDF tables can then be used in a traffic generation tool.  

=head1 OPTIONS

=over 22

=item -n <num_entries>

How many entries in the binding table

=item -tun_ip <ipv6>

Starting tunnel endpoint IPv6 address (will be incremented)

=item -mac <next_hop_mac>

MAC address of the next hop to reach the tunnel endpoints

=item -pub_ip <ipv4>

Starting public IPv4 address 

=item -port <begin>-<end>

Range of ports where to assign Port Sets

=item -set <num_ports>

Number of ports in set (should be a power of 2 because bitmasking is used
in lwAFTR)

=item -suffix <suffix>

Filename suffix to use for the generated file(s)

=item -test <num_entries>

Number of random entries to put into test UDF table

=item -sym

Whether the same random entry from the table should be inserted into both
traffic sides or if different entries should be used

=item -help

Shows the full script documentation.

=back

=head1 AUTHOR

 Copyright(c) 2010-2017 Intel Corporation.
 All rights reserved.

=cut


use strict vars;
use Getopt::Long;
use Pod::Usage;
use Socket qw(AF_INET AF_INET6 inet_ntop inet_pton);

sub parse_ip
{
        my ($str, $ip_ref, $family) = @_;

        my $packed = inet_pton($family, $str);
        return 0 if (!defined($packed));

        if ($family == AF_INET6) {
                #print unpack("H*", $packed). "\n";
                my @w = unpack("NNNN", $packed);
                my ($high, $low) = (($w[0] << 32) | $w[1], ($w[2] << 32) | $w[3]);
                @$ip_ref = ($high, $low);
        }
        else {
                $$ip_ref = unpack("N", $packed);
        }
        return 1;
}

sub ntop6
{
        my ($in) = @_;
        my $packed = pack('NNNN', $in->[0] >> 32, $in->[0] & 0xffffffff,
                                  $in->[1] >> 32, $in->[1] & 0xffffffff);
        return inet_ntop(AF_INET6, $packed);
}

sub ntop6_expanded
{
        my ($in) = @_;
        return sprintf('%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x',
                        ($in->[0] >> 48) & 0xffff, ($in->[0] >> 32) & 0xffff,
                        ($in->[0] >> 16) & 0xffff, ($in->[0]      ) & 0xffff,
                        ($in->[1] >> 48) & 0xffff, ($in->[1] >> 32) & 0xffff,
                        ($in->[1] >> 16) & 0xffff, ($in->[1]      ) & 0xffff);
}

my ($tun_ip_str, $pub_ip_str, $ports_str);

GetOptions(
        'help'     => sub () { Pod::Usage::pod2usage( -verbose => 2 ); exit; },
        'n=i'      => \(my $num_B4s = 10),
        'tun_ip=s' => \(my $tun_ip_str = 'fe80:0000:0000:0000:0200:00ff:0000:0000'),
        'pub_ip=s' => \(my $pub_ip_str = '171.205.239.1'),
        'mac=s'    => \(my $next_hop_mac = 'fe:80:00:00:00:00'),
        'port=s'   => \(my $ports_str='4608-11968'),
        'set=n'    => \(my $port_set_sz = 64),
        'suffix=s' => \(my $suffix = ''),
        'test=n'   => \(my $num_test_lines = 200000),
        'sym!'     => \(my $symmetric_traffic = TRUE),
) or pod2usage(-verbose => 1) && exit;

my @tun_ip;
parse_ip($tun_ip_str, \@tun_ip, AF_INET6) or print("Invalid starting tunnel IP: $tun_ip_str\n") && pod2usage(-verbose => 1) && exit;
parse_ip($pub_ip_str, \(my $pub_ip), AF_INET) or print("Invalid starting public IP: $pub_ip_str\n") && pod2usage(-verbose => 1) && exit;
my @port_range;
if ($ports_str =~ /^([^d]+)\s*\-\s*([^d]+)$/) {
        @port_range = ($1, $2);
}
else { print "Invalid port range: $ports_str\n"; pod2usage(-verbose => 1); exit }

# Summary of input data
print "File suffix: $suffix\n" if ($suffix);
print "Starting Tunnel IP: " . ntop6(\@tun_ip) . "\n";
print "Starting Public IP: ".inet_ntop(AF_INET, pack("N", $pub_ip)) . "\n";
print "Public Port Range: $port_range[0]-$port_range[1] by blocks of $port_set_sz\n";

my @data;  # Holds generated binding table, so we can later generate test traffic for it

# Binding table for PROX IPv6 Tunnel
my $filename = 'ip6_tun_bind'.$suffix.'.lua';
print "\nGenerating binding table with $num_B4s entries into $filename ... ";
open(my $fh, '>', $filename) or die "Could not open file '$filename' $!";
print $fh "-- Bindings for lwaftr: lwB4 IPv6 address, next hop MAC address\n";
print $fh "-- towards lwB4, IPv4 Public address, IPv4 Public Port Set\n";
print $fh "\n";
print $fh "return {" . "\n";
my $port = $port_range[0];
for (my $B4_id = 0; $B4_id < $num_B4s; $B4_id++) {
        $data[$B4_id]{'b4_ipv6'} = ntop6_expanded(\@tun_ip);
        $data[$B4_id]{'pub_ipv4'} = "" . (($pub_ip >> 24) & 0xff) . "." . (($pub_ip >> 16) & 0xff) . "." . (($pub_ip >> 8) & 0xff) . "." . ($pub_ip & 0xff);
        $data[$B4_id]{'pub_port'} = $port;
        $data[$B4_id]{'next_hop_mac'} = $next_hop_mac;

        print $fh "   {";
        print $fh "ip6 = ip6(\"" . $data[$B4_id]{'b4_ipv6'} . "\")";
        print $fh ", mac = mac(\"" . $data[$B4_id]{'next_hop_mac'} . "\")";
        print $fh ", ip = ip(\"" . $data[$B4_id]{'pub_ipv4'} . "\")";
        print $fh ", port = " . $data[$B4_id]{'pub_port'};
        print $fh "},\n";

        $port += $port_set_sz;
        if ($port > $port_range[1]) {
                $pub_ip++;
                $port = $port_range[0];
        }
        
        # Move to next Tunnel address
        if (@tun_ip[1] < 0xffffffffffffffff) {
                @tun_ip[1]++;
        } else {
                @tun_ip[0]++;
                @tun_ip[1] = 0;
        }
}
print $fh "}" . "\n";
close $fh;
print "[DONE]\n";

# Test traffic "UDF Tables"
if ($num_test_lines) {
        print "Generating $num_test_lines lines of test UDF table into lwAFTR_tun|inet".$suffix.".csv ... ";

        # Tunnel Packets from B4 to lwAFTR 
        my $filename = 'lwAFTR_tun' . $suffix . '.csv';
        open(my $fh_tun, '>', $filename) or die "Could not open file '$filename' $!";
        print $fh_tun "b4_ip,pub_ip,pub_port\n";
        print $fh_tun "22,66,74\n";  # Offsets
        print $fh_tun "16,4,2\n";    # Sizes
        print $fh_tun "6,5,3\n";     # Format (IPv6, IPv4, Decimal)
        print $fh_tun ",,\n";
        
        # Internet Packets towards the lwAFTR, to be sent to corresp lwB4 over tunnel 
        my $filename = 'lwAFTR_inet' . $suffix . '.csv';
        open(my $fh_inet, '>', $filename) or die "Could not open file '$filename' $!";
        print $fh_inet "pub_ip,pub_port\n";
        print $fh_inet "30,36\n";  # Offsets
        print $fh_inet "4,2\n";    # Sizes
        print $fh_inet "5,3\n";     # Format (IPv6, IPv4, Decimal)
        print $fh_inet ",,\n";

        for (my $i = 0; $i < $num_test_lines; $i++) {
                my $B4_id = int(rand($num_B4s));
                my $port = $data[$B4_id]{'pub_port'} + int(rand($port_set_sz)); 
                printf $fh_tun $data[$B4_id]{'b4_ipv6'} . "," . $data[$B4_id]{'pub_ipv4'} . "," . $port . "\n";
                
                if (! $symmetric_traffic) {
                        $B4_id = int(rand($num_B4s));
                        $port = $data[$B4_id]{'pub_port'} + int(rand($port_set_sz)); 
                }
                printf $fh_inet $data[$B4_id]{'pub_ipv4'} . "," . $port . "\n";
        }
        
        close $fh_tun;
        close $fh_inet;
        print "[DONE]\n";
}
