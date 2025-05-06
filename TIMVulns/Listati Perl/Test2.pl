#!/usr/bin/perl
use strict;
use warnings;
use CGI;
use DBI;
use MIME::Base64;
use IO::Socket::INET;
use Sys::Hostname;

sub f1 {

my $input = param('input'); # Assumendo uso di CGI
my @commands = split /;/, $input;
foreach my $cmd (@commands) {
    `$cmd`; # Iniezione concatenata
}


my $username = param('username'); # Assumendo uso di CGI
my $password = param('password'); # Assumendo uso di CGI
my $dbh = DBI->connect("DBI:mysql:database=test;host=localhost", "user", "password");
my $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
my $sth = $dbh->prepare($query);
$sth->execute();


my $remote_file = param('remote_file'); # Assumendo uso di CGI
require $remote_file; # Inclusione remota


use Storable qw(thaw);
my $serialized = param('serialized'); # Assumendo uso di CGI
my $object = thaw(decode_base64($serialized)); # Deserializzazione


my $user_input = param('user_input'); # Assumendo uso di CGI
print "<script>document.write('<div id=\"user\">$user_input</div>');</script>"; # XSS


my $filepath = param('filepath'); # Assumendo uso di CGI
open(my $fh, "<", "../../$filepath") or die "Errore: $!"; # Path Traversal


my $url = param('url'); # Assumendo uso di CGI
my $sock = IO::Socket::INET->new(PeerAddr => $url, PeerPort => 80);
print $sock "GET / HTTP/1.0\r\nHost: $url\r\n\r\n";
my @response = <$sock>;
print @response;


my $jwt = param('jwt'); # Assumendo uso di CGI
# Manca verifica della firma, consentendo la modifica del payload del JWT


my $location = param('location'); # Assumendo uso di CGI
print "Location: $location\r\n\r\n"; # Iniezione di header


my $dynamic_code = param('code'); # Assumendo uso di CGI
eval($dynamic_code); # Eval di codice dinamico


my $cookie_value = $CGI::cookie('cookie_name')->value;
print "Cookie Value: $cookie_value\n";


my $buffer = "A" x 1024;
my $user_data = param('user_data');
substr($buffer, 0, length($user_data), $user_data); # sovrascrittura buffer


my $file_to_open = param('file');
open(my $fh, "<", $file_to_open) or die "Cannot open file: $!"; # Leak di informazioni sui file.


$ENV{PATH} = param('new_path'); # manipolazione del PATH.


my $log_entry = param('log');
open(my $log_file, ">>", "/var/log/app.log");
print $log_file "$log_entry\n";

}