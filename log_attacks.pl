#!/usr/bin/perl

# Database for IP of people trying port scan or attacks on my public IP
# Database generated with:
#
# sqlite3 attackers.db
# create table attack_types(key INTEGER PRIMARY KEY, name TEXT);
# create table attackers(key INTEGER PRIMARY KEY, attack INTEGER, attacker TEXT,
#  port INTEGER, attack_date DATE, known BOOLEAN, locationcode NUMERIC,
#  fips104 TEXT, iso2 TEXT, iso3 TEXT, ison NUMERIC, internet TEXT,
#  countryid NUMERIC, country TEXT, regionid NUMERIC, region TEXT,
#  regioncode TEXT, adm1code TEXT, cityid NUMERIC, city TEXT, latitude REAL,
#  longitude REAL, timezone TEXT, certainty NUMERIC,
#  FOREIGN KEY(attack) REFERENCES attack_types(key));
# create table wlan(key INTEGER PRIMARY KEY, attack INTEGER, attack_date DATE,
#  mac TEXT, FOREIGN KEY(attack) REFERENCES attack_types(key));

use strict;
use DBI;
use Date::Parse;
use Net::Ping;
use Fcntl qw(:DEFAULT :flock);

# parameters
my $basedir = "$ENV{HOME}/UNIX/etc";

my $lockfile = "$ENV{TMPDIR}/log_attacks.pl.pid";
my $datafile = "$basedir/locate_attackers_IPs/list.txt";
my $logfile  = "$basedir/locate_attackers_IPs/log.txt";
my $dbfile   = "$basedir/locate_attackers_IPs/attackers.db";

open(LOCK, '>', $lockfile) || die "Error writing lock file $lockfile, $!\n";
flock(LOCK, LOCK_EX | LOCK_NB) || die "Error getting lock: already running script?\n";
print LOCK $$, "\n";

# checks for reachability of the iplocator and of Internet in general
check_online();
my $dbargs = {AutoCommit => 1, PrintError => 1};
my $dbh = DBI->connect("dbi:SQLite:dbname=$dbfile", "", "", $dbargs);
if ($dbh->err()) { die "$DBI::errstr\n"; }

# puts the whole file in memory, but keeps the file open and locked to avoid changes
open(INPUT, '<', $datafile) || die "Error reading $datafile, $!\n";
my @input = <INPUT>;
my @unprocessed;

my $iplocator_requests = 0;
my $limit_exceeded = 0;

while (@input > 0) {
	# takes first element and only at the end removes it if correctly processed
	my $line = $input[0];
	# empty line, remove and continue
	if ($line =~ /^\s*$/) {
#		print "Skipped white line\n";
		next;
	}
#	print $line;

	my $attack;
	my $ip;
	my $port;
	my $date;
	my $mac;
	my $attack_id;
	my %attacker_info;

	# this is a port scan or similar
	if (($attack, $ip, $port, $date) = ($line =~ m|^\[([^\]]+)\] from source: (\d+\.\d+\.\d+\.\d+), port (\d+), \S+, (.+)$|)) {
#		print "IPLocator request...\n";
#		next;
		my @curl_output = readpipe("curl -sS 'http://www.geobytes.com/IpLocator.htm?GetLocation&template=php3.txt&IpAddress=$ip'");
		foreach (@curl_output) {
#			print;
			/<meta name="([^"]+)" content="([^"]+)">/;
			$attacker_info{$1} = $2;
			last if ($2 eq "Limit exceeded");
		}
		
		# max 20 requests/hour to the iplocator: close input file, rewrites it without processed lines, wait, reopen it
		# the file gets closed to let other processes append further data
		if (exists $attacker_info{locationcode} and $attacker_info{locationcode} eq "Limit Exceeded") {
			print "Limit exceeded: ", scalar localtime(), "\n";
#			push(@unprocessed, "Limit exceeded: ", scalar localtime(), "\n");
			update_source();
			save_unprocessed();
			print "Waiting one hour for the next batch.\n";
			sleep 3630;
	
			check_online();
			open(INPUT, '<', $datafile) || die "Error reading $datafile, $!\n";
			@input = <INPUT>;
			$dbh = DBI->connect("dbi:SQLite:dbname=$dbfile", "", "", $dbargs);
			if ($dbh->err()) { die "$DBI::errstr\n"; }
			redo;
		}
		
		$attack_id = get_attack_id($attack);
		# dates in seconds from Epoch
		$date = str2time($date);
		
		# sometimes IP locations are unknown
		if ($attacker_info{known} eq "false") {
#			print "Not known: $line";
			$dbh->do("INSERT INTO attackers(attack, attacker, port, attack_date, known)
		 VALUES ($attack_id, \"$ip\", $port, $date, \"$attacker_info{known}\");");
		} else {
# 			print "INSERT INTO attackers(attack, attacker, port, attack_date, known, locationcode,
# 			  fips104, iso2, iso3, ison, internet, countryid, country, regionid, region, regioncode,
# 			  adm1code, cityid, city, latitude, longitude, timezone, certainty)
# 			 VALUES ($attack_id, '$ip', $port, $date, '$attacker_info{known}', '$attacker_info{locationcode}',
# 			  '$attacker_info{fips104}', '$attacker_info{iso2}', '$attacker_info{iso3}', $attacker_info{ison}, 
# 			  '$attacker_info{internet}', $attacker_info{countryid}, '$attacker_info{country}', 
# 			  '$attacker_info{regionid}', '$attacker_info{region}', '$attacker_info{regioncode}',
# 			  '$attacker_info{adm1code}', $attacker_info{cityid}, '$attacker_info{city}', 
# 			  '$attacker_info{latitude}', '$attacker_info{longitude}', '$attacker_info{timezone}', 
# 			  $attacker_info{certainty});\n";
# 			  
			$dbh->do("INSERT INTO attackers(attack, attacker, port, attack_date, known, locationcode,
			  fips104, iso2, iso3, ison, internet, countryid, country, regionid, region, regioncode,
			  adm1code, cityid, city, latitude, longitude, timezone, certainty)
			 VALUES ($attack_id, \"$ip\", $port, $date, \"$attacker_info{known}\", \"$attacker_info{locationcode}\",
			  \"$attacker_info{fips104}\", \"$attacker_info{iso2}\", \"$attacker_info{iso3}\", $attacker_info{ison}, 
			  \"$attacker_info{internet}\", $attacker_info{countryid}, \"$attacker_info{country}\", 
			  \"$attacker_info{regionid}\", \"$attacker_info{region}\", \"$attacker_info{regioncode}\",
			  \"$attacker_info{adm1code}\", $attacker_info{cityid}, \"$attacker_info{city}\", 
			  \"$attacker_info{latitude}\", \"$attacker_info{longitude}\", \"$attacker_info{timezone}\", 
			  $attacker_info{certainty});");
		}
		if ($dbh->err()) { update_source(); die "DBI error: $DBI::errstr\n"; }
		# "next" goes to the "continue" block
		next;

	# this is a bad WLAN access
	} elsif (($attack, $mac, $date) = ($line =~ m|^\[([^\]]+)\] from MAC address (\S+), \S+, (.+)$|)) {
#		print "WLAN access...\n";
#		next;
		# looks up the attack_type key, adds it if unknown
		$attack_id = get_attack_id($attack);
		
		$date = str2time($date);
		
		$dbh->do("INSERT INTO wlan(attack, attack_date, mac) VALUES ($attack_id, $date, '$mac');");
		if ($dbh->err()) { update_source(); die "$DBI::errstr\n"; }
		next;

	# other problems
	} else {
		print "Unmatched... $line";
		push(@unprocessed, $line);
		next;
	}
} continue {
#	$dbh->commit();
	shift(@input);
}
close(INPUT);
# at this point all lines are processed, clean the datafile
open(OUTPUT, '>', $datafile) || die "Error writing $datafile, $!\n";
close(OUTPUT);
save_unprocessed();

$dbh->disconnect();
close(LOCK);

exit 0;


sub check_online {
	my $p = Net::Ping->new();
	my $status = $p->ping('www.geobytes.com');
	$p->close();
	if ($status) {
		print "Ping failed: exiting.\n";
		exit 1;
	}
}

sub save_unprocessed {
	if (@unprocessed > 0) {
#		print @unprocessed;
		open (OUTPUT, '>>', $logfile) || die "Error writing $logfile, $!\n";
		foreach my $unmatched (@unprocessed) { print OUTPUT $unmatched; }
		close(OUTPUT);
		@unprocessed = undef;
	}
}

sub update_source {
	close(INPUT);
	$dbh->disconnect();
	open(OUTPUT, '>', $datafile) || die "Error writing $datafile, $!\n";
	print OUTPUT @input;
	close(OUTPUT);
}

sub get_attack_id {
	# looks up the attack_type key, adds it if unknown
	my $id = $dbh->selectrow_array("SELECT key FROM attack_types WHERE name=\"$_\";");
	if ($dbh->err()) { update_source(); die "DBI error: $DBI::errstr\n"; }
	if (!defined($id)) {
		$dbh->do("INSERT INTO attack_types (name) VALUES (\"$_\");");
		if ($dbh->err()) { update_source(); die "DBI error: $DBI::errstr\n"; }
		$id = $dbh->selectrow_array("SELECT key FROM attack_types WHERE name='$_';");
	}
	return $id;
}
