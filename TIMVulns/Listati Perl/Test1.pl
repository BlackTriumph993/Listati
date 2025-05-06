#!/usr/bin/perl
use strict;
use warnings;
use CGI;

sub f1 {
my $command = $ARGV[0];
my $output = `$command`;
print $output;


my $command2 = $ARGV[1];
system($command2);


my $format = $ARGV[2];
printf($format, "test");


my $id = param('id'); # Assumendo uso di CGI
my $query = "SELECT * FROM users WHERE id = '$id'";
# Esecuzione della query


my $file = param('file'); # Assumendo uso di CGI
require $file;


my $name = param('name'); # Assumendo uso di CGI
print "<div>$name</div>";


my $filepath = param('filepath'); # Assumendo uso di CGI
open(my $fh, "<", $filepath) or die "Errore: $!";
# ... lettura del file ...


use Storable qw(thaw);
my $serialized = param('serialized'); # Assumendo uso di CGI
my $data = thaw($serialized);


my $code = $ARGV[3];
eval($code);

}