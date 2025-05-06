#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use DBI;
use MIME::Base64;
use IO::Socket::INET;
use Sys::Hostname;
use POSIX;
use Fcntl qw(:flock);

sub f1 {
my $input = param('input');
$input =~ s/([^a-zA-Z0-9])/\\$1/g; # Tentativo di "sanificazione" fallace
open my $fh, "-|", "ls $input 2>&1" or die "Errore: $!";
while (<$fh>) { print $_; }


my $user_id = param('user_id');
my $binary_data = decode_base64(param('binary_data'));
my $dbh = DBI->connect("DBI:mysql:database=test;host=localhost", "user", "password");
my $query = "CALL update_user_data(?, ?)";
my $sth = $dbh->prepare($query);
$sth->bind_param(1, $user_id);
#$sth->bind_param(2, $binary_data, {TYPE => DBI::SQL_BLOB});
$sth->bind_param(2, $binary_data);
$sth->execute();

my $remote_file = param('remote_file')
{
    package Remote;
    our $secret = "original_secret"; # Variabile globale manipolabile
    require $remote_file; # Il file remoto può manipolare il namespace e la variabile
}


use Storable qw(thaw);
my $serialized_obj = decode_base64(param('obj'));
my $obj = thaw($serialized_obj); # Un attaccante potrebbe alterare il vtable dell'oggetto


my $svg_input = param('svg');
print "<svg onload=\"$svg_input\"></svg>"; # XSS via SVG


my $encoded_path = param('path');
$encoded_path =~ s/%252e%252e/\.\.\//gi; # Tentativo fallace di "sanificazione"
open my $file_handle, "<", $encoded_path or die "Errore: $!";
while (<$file_handle>) { print $_; }


my $target_url = param('target');
my ($protocol, $host, $port) = ($target_url =~ m{(https?://)([^:]+):?(\d*)}) or die "URL non valido";
$port ||= 80;
my $socket = IO::Socket::INET->new(PeerAddr => $host, PeerPort => $port, Proto => $protocol);
print $socket "GET / HTTP/1.1\r\nHost: $host\r\nConnection: close\r\n\r\n";
my @response = <$socket>; print @response;


my $session_cookie = $CGI::cookie('session_id')->value;
# Manca validazione del cookie e della sessione sul server.


my $header_value = param('header');
print "Content-Type: $header_value\r\n\r\n"; # Possibile iniezione e manipolazione di header


my $template = param('template');
my $code_to_eval = "sub { return \"$template\"; }"; # Possibile code injection via template
eval $code_to_eval->();


my $lockfile = "/tmp/myapp.lock";
open my $lock_fh, ">", $lockfile or die "Errore: $!";
flock $lock_fh, LOCK_EX | LOCK_NB; # Race condition se il file viene sostituito prima del lock.


my $logfile = "/var/log/myapp.log";
symlink "/dev/null", $logfile; # Race condition se il link viene cambiato dopo


$ENV{LD_PRELOAD} = param('lib'); # Iniezione di shared object via LD_PRELOAD


my $ipc_message = param('ipc');
system("some_ipc_handler $ipc_message");


my $config = param('config');
open my $config_file, ">", "/etc/myapp/config.conf";
print $config_file $config;
close $config_file;
}