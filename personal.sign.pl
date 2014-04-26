#!/bin/perl
#
# SMIME signer for CommuniGate CGP free (implemented as a Content-Filtering script)
#
# Version: 0.1
# 
# Copyright (c) 2009 Valera V.Kharseko. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#
# Written by vharseko@xxlive.ru.

use Crypt::SMIME;
use Getopt::Long;
use Pod::Usage;

my $personal_key_path="/var/CommuniGate/personal.keys";

sub Log {
	print "* $_[0]\n";
}
$| = 1;
Log "SMIME signer is running";Log "";
mkdir "Submitted" if ( !-d "Submitted" );
while (<>) {
	my @line = split( / /, $_ );
	chomp( $line[0] );
	print "$line[0] OK\n"     and next if ( $line[1] =~ /^quit$/i );
	print "$line[0] INTF 3\n" and next if ( $line[1] =~ /^intf$/i );
	print "$line[0] OK\n"     and next if ( $line[1] =~ /^key$/i );
	print "$line[0] FAILURE\n" and next if ( $line[1] !~ /^file$/i );    
	$line[2] =~ s|\\|/|g;              
	chomp( $line[2] );

	Log "SMIME signer process: $line[2]";
	
	if ( !open( MSG, $line[2] ) ) {
		Log "Error: file not found $line[2]";
		print "$line[0] OK\n";
	}
	else {
		my ( $sender, @recipients );
		#CGP headers
		while (1) {
			$line = <MSG>;
			chomp($line);
			last if ( $line eq '');
			if ( $line =~ /^(\w).+<(.+)>/ ) {
				if ( $1 eq 'P' ) {
					$sender = lc($2);
				}
				else {
					push @recipients, $2;
				}
			}
		}
		#mail headers and body
		my $EntireMessage=join("",<MSG>);
		close MSG;
		
				
		if ( $EntireMessage !~ /x-pkcs7-signature/i ) {
			if (open(FILE,"$personal_key_path/$sender"))
			{
				Log "SMIME sign from user=$sender ";
				
				#get keys 
				my $key;
  				$key = join("", <FILE>);
  				close FILE;
  				
  				#sign
  				my $smime = Crypt::SMIME->new();
  				$smime->setPrivateKey($key, $key,"1111");
  				my $signed=$smime->sign($EntireMessage);
  				$signed=~s/\r\n/\n/g;
  									
				my $alertFileName.="Submitted/A".time().int(rand(10000));
				open(SUBM,">$alertFileName.tmp");
				print SUBM $signed;
				close SUBM;
				rename("$alertFileName.tmp","$alertFileName.sub");
				print "$line[0] DISCARD\n";
				}
			else {
				Log "SMIME key not found $personal_key_path/$sender";	print "$line[0] OK\n";
			}
		}
		else {
			Log "SMIME signer skip (already signed): $line[2]";	print "$line[0] OK\n";
		}
	}
	open STDOUT, ">&STDOUT";
}
