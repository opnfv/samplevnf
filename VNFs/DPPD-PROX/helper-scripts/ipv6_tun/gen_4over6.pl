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

use strict vars;
use Getopt::Long;
use Pod::Usage;
use Net::Pcap;
use Net::Frame::Layer;
use Net::Frame::Layer::ETH qw(:consts);
use Net::Frame::Layer::IPv6 qw(:consts);
use Net::Frame::Layer::IPv4 qw(:consts);
use Net::Frame::Layer::UDP;
use Socket qw(AF_INET AF_INET6 inet_ntop inet_pton);

use constant NUM_PACKETS => 30000;

use constant ETHER_ADDR_LEN => 6;
use constant ETHER_TYPE_LEN => 2;
use constant ETHER_HDR_LEN => ( 2 * ETHER_ADDR_LEN ) + ETHER_TYPE_LEN;
use constant ETHER_STATIC_MAC => "78acdddddddd";

use constant UDP_HDR_LEN => 8;
use constant UDP_STATIC_PORT => 0x6666;

use constant IPv6_HOP_LIMIT => 4;
use constant IPv6_STATIC_IP => "2222:2222:2222:2222:2222:2222:2222:2222";

use constant IPv4_TIME_TO_LIVE => 32;
use constant IPv4_STATIC_IP => "68.68.68.68";

srand;

my $type = 'tun';
my $pkt_count = NUM_PACKETS;

GetOptions(
	'inet' => sub { $type = 'inet'},
	'tun' => sub { $type = 'tun'},
	'count=i'      => \$pkt_count,
	'in=s' => \(my $in = 'ip6_tun_bind.lua'),
	'out=s' => \(my $out = 'output.pcap'),
	'size=s' => \(my $size = 0)
) or exit;

my $pcap = pcap_open_dead( DLT_EN10MB, 65535 );
my $dumper = pcap_dump_open($pcap, $out ) or die 'Could not create output file: ' . $out;

if( $type eq 'inet' ) {
	gen_inet_pcap( $in, $pkt_count );
}
if( $type eq 'tun' ) {
	gen_tun_pcap( $in, $pkt_count );
}

pcap_close( $pcap );

# Trim string
sub trim {
	my ( $str ) = @_;

	$str =~ s/^\s+|\s+$//g;

	return $str;
}

# Generate random port based on $port and $port_mask
sub rand_port {
	my ( $port, $port_mask ) = @_;

	return ( $port | int( rand( 0xFFFF ) & $port_mask ) );
}

# Generate packet originating from CPE
sub gen_tun_packet {
	my ( $sz, $ether, $ipv6, $ipv4, $udp ) = @_;

	my $hdr_ether = Net::Frame::Layer::ETH->new(
		src => $ether->{'src'},
		dst => $ether->{'dst'},
		type => NF_ETH_TYPE_IPv6
	)->pack;

	my $hdr_ipv6 = Net::Frame::Layer::IPv6->new(
		nextHeader => NF_IPv6_PROTOCOL_IPIP,
		hopLimit => IPv6_HOP_LIMIT,
		src => $ipv6->{'src'},
		dst => $ipv6->{'dst'},
		payloadLength => $sz + NF_IPv4_HDR_LEN + UDP_HDR_LEN
	)->pack;

	my $hdr_ipv4 = Net::Frame::Layer::IPv4->new(
		length => $sz + UDP_HDR_LEN + NF_IPv4_HDR_LEN,
		ttl => IPv4_TIME_TO_LIVE,
		protocol => NF_IPv4_PROTOCOL_UDP,
		src => $ipv4->{'src'},
		dst => $ipv4->{'dst'}
	)->pack;

	my $hdr_udp = Net::Frame::Layer::UDP->new(
		src => $udp->{'src'},
		dst => $udp->{'dst'},
		length => $sz + UDP_HDR_LEN
	)->pack;
	
	my $pkt = pack( "H*", "de" x $sz );
	$pkt = $hdr_ether . $hdr_ipv6 . $hdr_ipv4 . $hdr_udp . $pkt;

	my $pkt_size = length( $pkt );

	my $hdr = {
		tv_sec => 0,
		tv_usec => 0,
		len => $pkt_size,
		caplen => $pkt_size
	};

	return ( $hdr, $pkt );
}

# Generate packet originating from the internet
sub gen_inet_packet {
	my ( $sz, $ether, $ipv4, $udp ) = @_;

	my $hdr_ether = Net::Frame::Layer::ETH->new(
		src => $ether->{'src'},
		dst => $ether->{'dst'},
		type => NF_ETH_TYPE_IPv4
	)->pack;

	my $hdr_ipv4 = Net::Frame::Layer::IPv4->new(
		length => $sz + UDP_HDR_LEN + NF_IPv4_HDR_LEN,
		ttl => IPv4_TIME_TO_LIVE,
		protocol => NF_IPv4_PROTOCOL_UDP,
		src => $ipv4->{'src'},
		dst => $ipv4->{'dst'}
	)->pack;

	my $hdr_udp = Net::Frame::Layer::UDP->new(
		src => $udp->{'src'},
		dst => $udp->{'dst'},
		length => $sz + UDP_HDR_LEN
	)->pack;
	
	my $pkt = pack( "H*", "de" x $sz );
	$pkt = $hdr_ether . $hdr_ipv4 . $hdr_udp . $pkt;

	my $pkt_size = length( $pkt );

	my $hdr = {
		tv_sec => 0,
		tv_usec => 0,
		len => $pkt_size,
		caplen => $pkt_size
	};

	return ( $hdr, $pkt );
}

# Read bindings file
sub read_bindings {
	my ( $file ) = @_;

	print "Reading bindings file...\n";

	my @rows;

	open my $fh, "<:encoding(utf8)", $file or die $file . ": $!";
LINE:	while ( my $line = <$fh> ) {
		next if ($line =~ /^--.*/);  # Skip comments
		
		my ($ip6, $mac, $ip4, $port);
		if ($line =~ /\s*\{.*\},\s*$/) {  # Weak check for a data line...

			$line =~ /ip6\s*=\s*ip6\("([^\)]*)"\)/ && do { $ip6 = trim($1); };
			unless ( inet_pton( AF_INET6, $ip6 ) ) { print "ERROR - Invalid ipv6: $ip6\n"; next LINE; }

			$line =~ /ip\s*=\s*ip\("([^\)]*)"\)/ && do { $ip4 = trim($1); };
			unless ( inet_pton( AF_INET, $ip4 ) ) { print "ERROR - Invalid ipv4: $ip4\n"; next LINE; }

			$line =~ /mac\s*=\s*mac\("([^\)]*)"\)/ && do { $mac = trim($1); };
			unless ( $mac =~ /^([0-9a-f]{2}([:-]|$)){6}$/i ) { print "ERROR - Invalid mac: $mac\n"; next LINE; }

			$line =~ /port\s*=\s*([0-9]*)/ && do { $port = trim($1); };
			unless ( int($port) ) { print "ERROR - Invalid port number: $port\n"; next LINE; }

			push @rows, {
				ipv6 => $ip6,
				mac => $mac,
				ipv4 => $ip4,
				port => $port
			}
		}
	}
	close $fh;

	return @rows;
}

# Generate packets originating from CPE
sub gen_tun_pcap {
	my ( $binding_file, $pkt_count ) = @_;
	my @bind = read_bindings($binding_file);
	my $idx = 0;
	my $row;
	my $public_port = 0;

	print "Generating $pkt_count Tunnel packets...\n";

	my $max = @bind;
	for( my $i=0; $i<$pkt_count; $i++ ) {

		$idx = rand $max;
		$row = @bind[$idx];

		$public_port = rand_port( $row->{port}, 0x3f );

		my ( $hdr, $pkt ) = gen_tun_packet(
			$size,
			{ src => $row->{mac}, dst => ETHER_STATIC_MAC },
			{ src => $row->{ipv6}, dst => IPv6_STATIC_IP },
			{ src => $row->{ipv4}, dst => IPv4_STATIC_IP },
			{ src => $public_port, dst => UDP_STATIC_PORT }
		);

		pcap_dump( $dumper, $hdr, $pkt );
	}
}

# Generate packets originating from the internet
sub gen_inet_pcap {
	my ( $binding_file, $pkt_count ) = @_;
	my @bind = read_bindings($binding_file);
	my $idx = 0;
	my $row;
	my $public_port = 0;

	print "Generating $pkt_count Internet packets...\n";

	my $max = @bind;
	for( my $i=0; $i<$pkt_count; $i++ ) {

		$idx = rand $max;
		$row = @bind[$idx];

		$public_port = rand_port( $row->{port}, 0x3f );

		my ( $hdr, $pkt ) = gen_inet_packet(
			$size,
			{ src => ETHER_STATIC_MAC, dst => $row->{mac} },
			{ src => IPv4_STATIC_IP, dst => $row->{ipv4} },
			{ src => UDP_STATIC_PORT, dst => $public_port }
		);

		pcap_dump( $dumper, $hdr, $pkt );
	}
}
