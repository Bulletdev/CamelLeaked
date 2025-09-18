#!/usr/bin/env perl
use strict;
use warnings;
use 5.024;

use FindBin;
use lib "$FindBin::Bin/../lib";

use Getopt::Long;
use Pod::Usage;
use CamelLeaked::Scanner;
use CamelLeaked::Rules;
use CamelLeaked::Notifier;

our $VERSION = '1.0.0';

=head1 NAME

camel-leaked - A tool to scan for hardcoded secrets in code changes

=head1 SYNOPSIS

    camel-leaked [OPTIONS]

    # Scan diff from STDIN
    git diff | camel-leaked

    # Scan specific diff file
    camel-leaked --diff-file changes.diff

    # Use custom rules configuration
    camel-leaked --config custom-rules.json

=head1 DESCRIPTION

CamelLeaked is a security tool designed to detect hardcoded secrets (API keys,
passwords, tokens, etc.) in code changes. It analyzes git diffs using regex
patterns and entropy detection to identify potential security leaks.

=head1 OPTIONS

=over 4

=item B<--diff-file PATH>

Path to diff file to scan (default: reads from STDIN)

=item B<--config PATH>

Path to rules configuration file (default: config/rules.json)

=item B<--no-email>

Disable email notifications

=item B<--help>

Show this help message

=item B<--version>

Show version information

=back

=cut

my %opt = (
    'diff-file' => undef,
    'config'    => 'config/rules.json',
    'no-email'  => 0,
    'help'      => 0,
    'version'   => 0,
);

GetOptions(
    'diff-file=s' => \$opt{'diff-file'},
    'config=s'    => \$opt{'config'},
    'no-email'    => \$opt{'no-email'},
    'help|h'      => \$opt{'help'},
    'version|v'   => \$opt{'version'},
) or pod2usage(2);

if ($opt{help}) {
    pod2usage(1);
}

if ($opt{version}) {
    say "camel-leaked version $VERSION";
    exit 0;
}

sub main {
    my $diff_content;

    if ($opt{'diff-file'}) {
        if (! -f $opt{'diff-file'}) {
            die "Error: Diff file '$opt{'diff-file'}' not found\n";
        }

        open my $fh, '<', $opt{'diff-file'}
            or die "Error: Cannot read diff file '$opt{'diff-file'}': $!\n";

        $diff_content = do { local $/; <$fh> };
        close $fh;
    } else {
        $diff_content = do { local $/; <STDIN> };
    }

    unless ($diff_content) {
        say "No diff content provided";
        exit 0;
    }

    my $rules = CamelLeaked::Rules->new(config_file => $opt{config});
    eval {
        $rules->load_rules();
    };
    if ($@) {
        die "Error loading rules: $@\n";
    }

    my $scanner = CamelLeaked::Scanner->new(rules => $rules);
    my @findings = $scanner->scan_diff($diff_content);

    if (@findings) {
        say "🚨 SECRET LEAK DETECTED! 🚨";
        say "";
        say "The following potential secrets were found in the diff:";
        say "";

        for my $finding (@findings) {
            say "File: $finding->{file}";
            say "Line: $finding->{line_number}" if defined $finding->{line_number};
            say "Rule: $finding->{rule_name}";
            say "Content: $finding->{content}";
            say "Context: $finding->{context}" if $finding->{context};
            say "---";
        }

        unless ($opt{'no-email'}) {
            eval {
                my $notifier = CamelLeaked::Notifier->new();
                $notifier->send_notification(\@findings);
                say "📧 Notification email sent to commit author";
            };
            if ($@) {
                warn "Warning: Failed to send email notification: $@\n";
            }
        }

        exit 1;
    } else {
        say "✅ No secrets detected in the diff";
        exit 0;
    }
}

main() unless caller;

__END__

=head1 ENVIRONMENT VARIABLES

=over 4

=item B<SMTP_HOST>

SMTP server hostname for email notifications

=item B<SMTP_PORT>

SMTP server port (default: 587)

=item B<SMTP_USER>

SMTP username for authentication

=item B<SMTP_PASS>

SMTP password for authentication

=item B<GITHUB_TOKEN>

GitHub API token for accessing PR information

=item B<GITHUB_REPOSITORY>

GitHub repository in format owner/repo

=item B<GITHUB_EVENT_PATH>

Path to GitHub event payload file

=back

=head1 EXIT STATUS

=over 4

=item B<0> - No secrets found

=item B<1> - Secrets detected

=item B<2> - Error in execution

=back

=head1 EXAMPLES

    # Basic usage in CI/CD
    git diff origin/main...HEAD | camel-leaked

    # With custom configuration
    camel-leaked --config production-rules.json --diff-file changes.diff

    # Disable email notifications
    git diff | camel-leaked --no-email

=head1 AUTHOR

Security Engineering Team

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2024.

=cut