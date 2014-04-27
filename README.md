communigate-smime
=================

SMIME signer for CommuniGate CGP free (implemented as a Content-Filtering script)

External library
=================

cpan install Crypt::SMIME

cpan install Getopt::Long

cpan install Pod::Usage

How-to config
===========================

/var/CommuniGate/Settings/Main.settings

ExternalFilters = ({Enabled=YES;LogLevel=5;Name=SMIME;ProgramName="/usr/bin/perl /var/CommuniGate/sign.pl";RestartPause=5s;Timeout=10m;});

/var/CommuniGate/Settings/Rules.settings

(
 (
    0,
    "SIGN SMIME",
    (
      (Source, in, "trusted,authenticated"),
      (Security, "not in", "*encrypted*,*signed*"),
      ("Any Route", is, "SMTP*")
    ),
    ((ExternalFilter, SMIME))
  )
)
