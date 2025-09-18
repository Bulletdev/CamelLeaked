package CamelLeaked::Scanner;
use strict;
use warnings;
use 5.024;

use Moo;
use MIME::Base64 qw(decode_base64);
use Carp qw(croak);

=head1 NAME

CamelLeaked::Scanner - Core scanning engine for detecting secrets in diffs

=head1 SYNOPSIS

    use CamelLeaked::Scanner;
    use CamelLeaked::Rules;

    my $rules = CamelLeaked::Rules->new(config_file => 'rules.json');
    $rules->load_rules();

    my $scanner = CamelLeaked::Scanner->new(rules => $rules);
    my @findings = $scanner->scan_diff($diff_content);

=head1 DESCRIPTION

This module provides the core scanning functionality for CamelLeaked. It can
analyze git diffs using regex patterns and entropy detection to identify
potential hardcoded secrets.

=cut

has 'rules' => (
    is       => 'ro',
    required => 1,
);

has 'min_entropy' => (
    is      => 'ro',
    default => 4.5,
);

has 'min_length' => (
    is      => 'ro',
    default => 20,
);

=head1 METHODS

=head2 scan_diff($diff_content)

Scans a git diff for potential secrets. Returns an array of findings.

Each finding is a hashref with the following keys:
- file: The filename where the secret was found
- line_number: The line number (if available)
- rule_name: The name of the rule that matched
- content: The actual content that matched
- context: Additional context around the match

=cut

sub scan_diff {
    my ($self, $diff_content) = @_;

    return () unless $diff_content;

    my @findings;
    my $current_file = '';
    my $line_number = 0;

    for my $line (split /\n/, $diff_content) {
        if ($line =~ /^\+\+\+ b\/(.+)$/) {
            $current_file = $1;
            $line_number = 0;
            next;
        }

        if ($line =~ /^@@ -\d+,?\d* \+(\d+),?\d* @@/) {
            $line_number = $1 - 1;
            next;
        }

        if ($line =~ /^[\+\-\s]/) {
            $line_number++ if $line =~ /^[\+\s]/;
        }

        next unless $line =~ /^\+/;

        my $content = substr($line, 1);

        next if $self->_should_ignore_line($content);

        for my $rule (@{$self->rules->get_rules()}) {
            if (my @matches = $content =~ /$rule->{pattern}/g) {
                for my $match (@matches) {
                    push @findings, {
                        file        => $current_file,
                        line_number => $line_number,
                        rule_name   => $rule->{name},
                        content     => $match,
                        context     => $content,
                    };
                }
            }
        }

        my @entropy_findings = $self->_check_entropy($content, $current_file, $line_number);
        push @findings, @entropy_findings;
    }

    return @findings;
}

=head2 _should_ignore_line($line)

Checks if a line should be ignored based on ignore comments.

=cut

sub _should_ignore_line {
    my ($self, $line) = @_;

    return 1 if $line =~ /(?:#|\/\/)\s*camel-leaked-ignore/;

    return 1 if $line =~ /^\s*[#\/\*]/;

    return 0;
}

=head2 _check_entropy($content, $file, $line_number)

Performs entropy analysis on content to detect high-entropy strings
that might be secrets.

=cut

sub _check_entropy {
    my ($self, $content, $file, $line_number) = @_;

    my @findings;

    my @tokens = $content =~ /([A-Za-z0-9+\/=]{20,})/g;

    for my $token (@tokens) {
        next if length($token) < $self->min_length;

        my $entropy = $self->_calculate_entropy($token);

        if ($entropy >= $self->min_entropy) {
            next if $self->_is_common_string($token);

            push @findings, {
                file        => $file,
                line_number => $line_number,
                rule_name   => 'High Entropy String',
                content     => $token,
                context     => $content,
            };
        }
    }

    return @findings;
}

=head2 _calculate_entropy($string)

Calculates the Shannon entropy of a string.

=cut

sub _calculate_entropy {
    my ($self, $string) = @_;

    return 0 unless $string;

    my %char_count;
    my $length = length($string);

    for my $char (split //, $string) {
        $char_count{$char}++;
    }

    my $entropy = 0;
    for my $count (values %char_count) {
        my $probability = $count / $length;
        $entropy -= $probability * log($probability) / log(2);
    }

    return $entropy;
}

=head2 _is_common_string($string)

Checks if a string is a common/known non-secret string that should be ignored.

=cut

sub _is_common_string {
    my ($self, $string) = @_;

    my @common_patterns = (
        qr/^[A-Za-z0-9+\/]*={0,2}$/,  # Base64-like but common
        qr/^[0-9a-f]{32,64}$/i,       # Hex hashes (but could be secrets)
        qr/^test/i,                   # Test strings
        qr/^example/i,                # Example strings
        qr/^demo/i,                   # Demo strings
        qr/^placeholder/i,            # Placeholder strings
    );

    for my $pattern (@common_patterns) {
        return 1 if $string =~ $pattern && length($string) < 40;
    }

    return 1 if $string =~ /^[A-Z0-9_]{20,}$/ && $string !~ /[a-z]/;

    return 0;
}

=head2 scan_content($content, $filename)

Scans arbitrary content (not necessarily a diff) for secrets.

=cut

sub scan_content {
    my ($self, $content, $filename) = @_;

    $filename //= 'unknown';

    my @findings;
    my $line_number = 1;

    for my $line (split /\n/, $content) {
        next if $self->_should_ignore_line($line);

        for my $rule (@{$self->rules->get_rules()}) {
            if (my @matches = $line =~ /$rule->{pattern}/g) {
                for my $match (@matches) {
                    push @findings, {
                        file        => $filename,
                        line_number => $line_number,
                        rule_name   => $rule->{name},
                        content     => $match,
                        context     => $line,
                    };
                }
            }
        }

        my @entropy_findings = $self->_check_entropy($line, $filename, $line_number);
        push @findings, @entropy_findings;

        $line_number++;
    }

    return @findings;
}

1;

__END__

=head1 AUTHOR

Security Engineering Team

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2024.

=cut