#!/usr/bin/perl

use strict;
use warnings;
use IO::Select;
use IO::Socket::INET;
use IO::Socket::SSL;

my $upstream_host = shift @ARGV;
my $cert = shift @ARGV;
my $listen_addr = shift @ARGV || "127.0.0.1:5432";
my $upstream_port = shift @ARGV || 5432;
die "Usage: $0 upstream_host cert_and_key.pem [listen_addr=127.0.0.1:5432] [upstream_port=5432]" if(!$upstream_host);

my $upstream_addr = "$upstream_host:$upstream_port";
my $s = IO::Select->new();


my $listen_sock = IO::Socket::INET->new(Listen    => 5,
								 ReuseAddr => 1,
                                 LocalAddr => $listen_addr,
                                 Proto     => 'tcp') or die "Cant listen on $listen_addr: $!";

$s->add($listen_sock);

mydebug("Listening on $listen_addr, awaiting connections");

my %upstreams;
my %clients;
while (my @ready = $s->can_read()) {
	for my $a_sock (@ready) {
		eval {
			if($a_sock == $listen_sock) {
				my $client_sock = $listen_sock->accept();			
				my $peer_host = $client_sock->peerhost();
				my $peer_port = $client_sock->peerport();
				my $peer_addr = "$peer_host:$peer_port";
				mydebug("New connection from $peer_addr, connecting to upstream: $upstream_addr");
				my $upstream_sock = IO::Socket::INET->new(PeerAddr => "$upstream_host:$upstream_port") or die "cant connect to upstream: $!";
				mydebug("Connection established with upstream: $upstream_addr");
				$s->add($client_sock);
				$s->add($upstream_sock);
				
				#print "upstream sock: $upstream_sock\n";
				#print "client sock: $client_sock\n";
				
				$upstreams{$upstream_sock} = $client_sock;
				$clients{$client_sock} = $upstream_sock;
			}
			elsif(my $client_sock = $upstreams{$a_sock}) {
				my $upstream_sock = $a_sock;
				my $buf;
				if(my $r = sysread($upstream_sock, $buf, 4096)) {
				   print_hexdump("S->C", $buf);
				   my $w = syswrite($client_sock, $buf);
				   die "Unable to write everything $r != $w" if($w != $r);
				} else {
				   disc("upstream disconnected", $upstream_sock, $client_sock);
				}
				
				if((length($buf) == 1) and ($buf eq "S") and ("$upstream_sock" !~ /SSL/)) {
					mydebug("STARTTLS");
										
					my $upstream_before = "$upstream_sock";
					if(!IO::Socket::SSL->start_SSL($upstream_sock, SSL_verify_mode => SSL_VERIFY_NONE)) {
						disc("failed to tls handshake with upstream", $upstream_sock, $client_sock);
					}
					mydebug("Server switched to TLS");
					my $upstream_after = "$upstream_sock";
					$upstreams{$upstream_after} = $upstreams{$upstream_before};
					delete($upstreams{$upstream_before});
					
					# SSL upgrade client (in new process/thread)
					my $client_before = "$client_sock";
					if(!IO::Socket::SSL->start_SSL($client_sock,
						SSL_server => 1,
						SSL_cert_file => $cert,
						SSL_key_file => $cert,
					)) {
					  disc("failed to tls handshake with client: $SSL_ERROR", $upstream_sock, $client_sock);
					}
					mydebug("Client switched to TLS");
					my $client_after = "$client_sock";
					$clients{$client_after} = $clients{$client_before};
					delete($clients{$client_before});
					

				}
			}
			elsif(my $upstream_sock = $clients{$a_sock}) {
				my $client_sock = $a_sock;
				my $buf;
				if(my $r = sysread($client_sock, $buf, 4096)) {
				   print_hexdump("C->S", $buf);
				   my $w = syswrite($upstream_sock, $buf);
				   die "Unable to write everything $r != $w" if($w != $r);
				} else {
				   disc("client disconnected", $upstream_sock, $client_sock);
				}
			}else{
				mydebug("shouldnt happen:( $a_sock");
			}

		};
		if($@) {
			mydebug("error during operation: $@");
		}
	}	
}

sub mydebug {
	my $msg = shift;
	my $now = localtime;
	print STDERR "[$now] $msg\n";	
}

sub disc {
   my ($msg, $upstream_sock, $client_sock) = @_;
   close($upstream_sock);
   close($client_sock);
   delete($upstreams{$upstream_sock});
   delete($clients{$client_sock});	
   $s->remove($client_sock);
   $s->remove($upstream_sock);
   die($msg);
}

sub print_hexdump {
	my ($head, $data) = @_;
	mydebug("$head:\n".hexdump($data));
}

#https://www.perlmonks.org/?node_id=132401
sub hexdump {
    my $str = ref $_[0] ? ${$_[0]} : $_[0];

    return "[ZERO-LENGTH STRING]\n" unless length $str;

    # split input up into 16-byte chunks:
    my @chunks = $str =~ /([\0-\377]{1,16})/g;
    # format and print:
    my @print;
    for (@chunks) {
        my $hex = unpack "H*", $_;
        tr/ -~/./c;                   # mask non-print chars
        $hex =~ s/(..)(?!$)/$1 /g;      # insert spaces in hex
        # make sure our hex output has the correct length
        $hex .= ' ' x ( length($hex) < 48 ? 48 - length($hex) : 0 );
        push @print, "$hex $_\n";
    }
    wantarray ? @print : join '', @print;
}

