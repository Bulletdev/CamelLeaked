package CamelLeaked::Notifier;
use strict;
use warnings;
use 5.024;

use Moo;
use Email::Stuffer;
use Mojo::UserAgent;
use JSON::MaybeXS qw(decode_json);
use Carp qw(croak);

=head1 NAME

CamelLeaked::Notifier - Email notification system for secret detection alerts

=head1 SYNOPSIS

    use CamelLeaked::Notifier;

    my $notifier = CamelLeaked::Notifier->new();
    $notifier->send_notification(\@findings);

=head1 DESCRIPTION

This module handles sending email notifications when secrets are detected.
It integrates with GitHub Actions to get commit author information and
sends detailed reports via SMTP.

=cut

has 'smtp_host' => (
    is      => 'ro',
    default => sub { $ENV{SMTP_HOST} // 'localhost' },
);

has 'smtp_port' => (
    is      => 'ro',
    default => sub { $ENV{SMTP_PORT} // 587 },
);

has 'smtp_user' => (
    is      => 'ro',
    default => sub { $ENV{SMTP_USER} // '' },
);

has 'smtp_pass' => (
    is      => 'ro',
    default => sub { $ENV{SMTP_PASS} // '' },
);

has 'from_email' => (
    is      => 'ro',
    default => sub { $ENV{FROM_EMAIL} // 'security@company.com' },
);

has 'github_token' => (
    is      => 'ro',
    default => sub { $ENV{GITHUB_TOKEN} // '' },
);

has 'github_repository' => (
    is      => 'ro',
    default => sub { $ENV{GITHUB_REPOSITORY} // '' },
);

has 'github_event_path' => (
    is      => 'ro',
    default => sub { $ENV{GITHUB_EVENT_PATH} // '' },
);

has 'ua' => (
    is      => 'ro',
    default => sub { Mojo::UserAgent->new() },
);

=head1 METHODS

=head2 send_notification(\@findings)

Sends an email notification with the provided findings. Attempts to get
the commit author's email from GitHub API.

=cut

sub send_notification {
    my ($self, $findings) = @_;

    unless ($findings && @$findings) {
        return;
    }

    my $recipient_email = $self->_get_author_email();
    unless ($recipient_email) {
        warn "Warning: Could not determine recipient email address\n";
        return;
    }

    my $subject = sprintf(
        "🚨 SECURITY ALERT: Secrets detected in %s",
        $self->github_repository || 'repository'
    );

    my $body = $self->_build_email_body($findings);

    eval {
        $self->_send_email($recipient_email, $subject, $body);
    };
    if ($@) {
        croak "Failed to send email notification: $@";
    }

    return 1;
}

=head2 _get_author_email()

Attempts to get the commit author's email from GitHub API or event data.

=cut

sub _get_author_email {
    my ($self) = @_;

    my $email = $self->_get_email_from_event();
    return $email if $email;

    $email = $self->_get_email_from_api();
    return $email if $email;

    return;
}

=head2 _get_email_from_event()

Extracts email from GitHub event payload file.

=cut

sub _get_email_from_event {
    my ($self) = @_;

    return unless $self->github_event_path && -f $self->github_event_path;

    my $content;
    eval {
        open my $fh, '<', $self->github_event_path
            or die "Cannot open event file: $!";
        $content = do { local $/; <$fh> };
        close $fh;
    };
    return if $@;

    my $event;
    eval {
        $event = decode_json($content);
    };
    return if $@;

    my $email;

    if ($event->{pull_request} && $event->{pull_request}{user}) {
        $email = $event->{pull_request}{user}{email};
    }

    if (!$email && $event->{commits} && @{$event->{commits}}) {
        $email = $event->{commits}[0]{author}{email};
    }

    if (!$email && $event->{head_commit}) {
        $email = $event->{head_commit}{author}{email};
    }

    return $email;
}

=head2 _get_email_from_api()

Attempts to get email from GitHub API using the GitHub token.

=cut

sub _get_email_from_api {
    my ($self) = @_;

    return unless $self->github_token && $self->github_repository;

    my $headers = {
        'Authorization' => 'token ' . $self->github_token,
        'Accept'        => 'application/vnd.github.v3+json',
        'User-Agent'    => 'CamelLeaked/1.0',
    };

    my $event_data = $self->_get_event_data();
    return unless $event_data;

    my $username = $event_data->{username};
    return unless $username;

    my $url = "https://api.github.com/users/$username";

    my $tx = $self->ua->get($url => $headers);

    unless ($tx->result->is_success) {
        warn "Failed to get user info from GitHub API: " . $tx->result->message . "\n";
        return;
    }

    my $user_data = $tx->result->json;
    return $user_data->{email} if $user_data && $user_data->{email};

    return;
}

=head2 _get_event_data()

Extracts relevant data from GitHub event for API calls.

=cut

sub _get_event_data {
    my ($self) = @_;

    return unless $self->github_event_path && -f $self->github_event_path;

    my $content;
    eval {
        open my $fh, '<', $self->github_event_path
            or die "Cannot open event file: $!";
        $content = do { local $/; <$fh> };
        close $fh;
    };
    return if $@;

    my $event;
    eval {
        $event = decode_json($content);
    };
    return if $@;

    my $username;

    if ($event->{pull_request} && $event->{pull_request}{user}) {
        $username = $event->{pull_request}{user}{login};
    } elsif ($event->{pusher}) {
        $username = $event->{pusher}{name};
    } elsif ($event->{sender}) {
        $username = $event->{sender}{login};
    }

    return { username => $username };
}

=head2 _build_email_body(\@findings)

Builds the email body content from findings.

=cut

sub _build_email_body {
    my ($self, $findings) = @_;

    my $body = "SECURITY ALERT: Hardcoded Secrets Detected\n\n";

    $body .= "Repository: " . ($self->github_repository || 'Unknown') . "\n";
    $body .= "Detection Time: " . localtime() . "\n";
    $body .= "Number of Secrets Found: " . scalar(@$findings) . "\n\n";

    $body .= "🚨 IMMEDIATE ACTION REQUIRED 🚨\n\n";

    $body .= "The following potential secrets have been detected in your code changes:\n\n";

    for my $i (0 .. $#$findings) {
        my $finding = $findings->[$i];
        $body .= sprintf("Finding #%d:\n", $i + 1);
        $body .= "  File: $finding->{file}\n";
        $body .= "  Line: $finding->{line_number}\n" if defined $finding->{line_number};
        $body .= "  Rule: $finding->{rule_name}\n";
        $body .= "  Detected Content: $finding->{content}\n";

        if ($finding->{context}) {
            my $context = $finding->{context};
            $context = substr($context, 0, 100) . '...' if length($context) > 100;
            $body .= "  Context: $context\n";
        }

        $body .= "\n";
    }

    $body .= "WHAT YOU NEED TO DO:\n\n";
    $body .= "1. 🛑 STOP - Do not merge this pull request\n";
    $body .= "2. 🔍 Review each detected secret immediately\n";
    $body .= "3. 🔄 Remove or replace hardcoded secrets with:\n";
    $body .= "   - Environment variables\n";
    $body .= "   - Secure configuration files (not in git)\n";
    $body .= "   - Secret management services\n";
    $body .= "4. 🗑️  If real secrets were committed:\n";
    $body .= "   - Rotate/regenerate the compromised credentials\n";
    $body .= "   - Update services using these credentials\n";
    $body .= "5. ✅ Test that your changes work with the new approach\n";
    $body .= "6. 🔁 Re-run the security scan to confirm fixes\n\n";

    $body .= "If you believe these are false positives, you can add:\n";
    $body .= "# camel-leaked-ignore\n";
    $body .= "at the end of the line to suppress the warning.\n\n";

    $body .= "For questions or assistance, contact the Security Team.\n\n";

    $body .= "---\n";
    $body .= "This alert was generated automatically by CamelLeaked\n";
    $body .= "Security is everyone's responsibility! 🔒\n";

    return $body;
}

=head2 _send_email($to, $subject, $body)

Sends an email using Email::Stuffer and SMTP configuration.

=cut

sub _send_email {
    my ($self, $to, $subject, $body) = @_;

    unless ($self->smtp_host) {
        croak "SMTP host not configured";
    }

    my $email = Email::Stuffer
        ->from($self->from_email)
        ->to($to)
        ->subject($subject)
        ->text_body($body);

    if ($self->smtp_user && $self->smtp_pass) {
        $email->transport(
            'SMTP',
            host     => $self->smtp_host,
            port     => $self->smtp_port,
            sasl_username => $self->smtp_user,
            sasl_password => $self->smtp_pass,
            ssl      => ($self->smtp_port == 465) ? 1 : 0,
            tls      => ($self->smtp_port == 587) ? 1 : 0,
        );
    } else {
        $email->transport(
            'SMTP',
            host => $self->smtp_host,
            port => $self->smtp_port,
        );
    }

    $email->send();

    return 1;
}

=head2 test_email_config()

Tests the email configuration by sending a test message.

=cut

sub test_email_config {
    my ($self) = @_;

    eval {
        $self->_send_email(
            $self->from_email,
            'CamelLeaked Configuration Test',
            'This is a test email from CamelLeaked to verify SMTP configuration.'
        );
    };

    return $@ ? 0 : 1;
}

1;

__END__

=head1 ENVIRONMENT VARIABLES

This module uses the following environment variables for configuration:

=over 4

=item B<SMTP_HOST> - SMTP server hostname

=item B<SMTP_PORT> - SMTP server port (default: 587)

=item B<SMTP_USER> - SMTP username for authentication

=item B<SMTP_PASS> - SMTP password for authentication

=item B<FROM_EMAIL> - From email address (default: security@company.com)

=item B<GITHUB_TOKEN> - GitHub API token

=item B<GITHUB_REPOSITORY> - Repository name (owner/repo)

=item B<GITHUB_EVENT_PATH> - Path to GitHub event JSON file

=back

=head1 AUTHOR

Security Engineering Team

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2024.

=cut