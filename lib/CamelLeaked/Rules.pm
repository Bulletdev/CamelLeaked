package CamelLeaked::Rules;
use strict;
use warnings;
use 5.024;

use Moo;
use JSON::MaybeXS qw(decode_json);
use File::Slurp qw(read_file);
use Carp qw(croak);

=head1 NAME

CamelLeaked::Rules - Rule management for secret detection patterns

=head1 SYNOPSIS

    use CamelLeaked::Rules;

    my $rules = CamelLeaked::Rules->new(config_file => 'config/rules.json');
    $rules->load_rules();

    my @rules = @{$rules->get_rules()};

=head1 DESCRIPTION

This module handles loading and managing detection rules from JSON configuration
files. Rules consist of regex patterns and metadata for identifying different
types of secrets.

=cut

has 'config_file' => (
    is       => 'ro',
    required => 1,
);

has '_rules' => (
    is      => 'rw',
    default => sub { [] },
);

=head1 METHODS

=head2 load_rules()

Loads rules from the configuration file. Dies on error.

=cut

sub load_rules {
    my ($self) = @_;

    unless (-f $self->config_file) {
        croak "Rules configuration file not found: " . $self->config_file;
    }

    my $content;
    eval {
        $content = read_file($self->config_file, { binmode => ':utf8' });
    };
    if ($@) {
        croak "Cannot read rules file: $@";
    }

    my $config;
    eval {
        $config = decode_json($content);
    };
    if ($@) {
        croak "Invalid JSON in rules file: $@";
    }

    unless (ref $config eq 'HASH' && exists $config->{rules}) {
        croak "Rules file must contain a 'rules' array";
    }

    unless (ref $config->{rules} eq 'ARRAY') {
        croak "Rules configuration must be an array";
    }

    my @validated_rules;
    for my $i (0 .. $#{$config->{rules}}) {
        my $rule = $config->{rules}[$i];

        unless (ref $rule eq 'HASH') {
            croak "Rule $i must be an object/hash";
        }

        unless (exists $rule->{name} && defined $rule->{name} && $rule->{name} ne '') {
            croak "Rule $i missing required 'name' field";
        }

        unless (exists $rule->{pattern} && defined $rule->{pattern} && $rule->{pattern} ne '') {
            croak "Rule $i missing required 'pattern' field";
        }

        eval { qr/$rule->{pattern}/ };
        if ($@) {
            croak "Rule $i has invalid regex pattern: $@";
        }

        my $validated_rule = {
            name        => $rule->{name},
            pattern     => qr/$rule->{pattern}/,
            description => $rule->{description} // '',
            example     => $rule->{example} // '',
            enabled     => exists $rule->{enabled} ? $rule->{enabled} : 1,
        };

        next unless $validated_rule->{enabled};

        push @validated_rules, $validated_rule;
    }

    unless (@validated_rules) {
        croak "No valid enabled rules found in configuration";
    }

    $self->_rules(\@validated_rules);

    return scalar @validated_rules;
}

=head2 get_rules()

Returns arrayref of loaded rules.

=cut

sub get_rules {
    my ($self) = @_;
    return $self->_rules;
}

=head2 get_rule_by_name($name)

Returns a specific rule by name, or undef if not found.

=cut

sub get_rule_by_name {
    my ($self, $name) = @_;

    for my $rule (@{$self->_rules}) {
        return $rule if $rule->{name} eq $name;
    }

    return;
}

=head2 add_rule(%rule_data)

Adds a new rule at runtime. Useful for testing.

=cut

sub add_rule {
    my ($self, %rule_data) = @_;

    unless (exists $rule_data{name} && defined $rule_data{name} && $rule_data{name} ne '') {
        croak "Rule missing required 'name' field";
    }

    unless (exists $rule_data{pattern} && defined $rule_data{pattern} && $rule_data{pattern} ne '') {
        croak "Rule missing required 'pattern' field";
    }

    eval { qr/$rule_data{pattern}/ };
    if ($@) {
        croak "Rule has invalid regex pattern: $@";
    }

    my $rule = {
        name        => $rule_data{name},
        pattern     => qr/$rule_data{pattern}/,
        description => $rule_data{description} // '',
        example     => $rule_data{example} // '',
        enabled     => exists $rule_data{enabled} ? $rule_data{enabled} : 1,
    };

    push @{$self->_rules}, $rule;

    return 1;
}

=head2 rule_count()

Returns the number of loaded rules.

=cut

sub rule_count {
    my ($self) = @_;
    return scalar @{$self->_rules};
}

=head2 validate_config_file($file_path)

Static method to validate a rules configuration file without loading it.
Returns 1 on success, dies on error.

=cut

sub validate_config_file {
    my ($class, $file_path) = @_;

    unless (-f $file_path) {
        croak "Rules configuration file not found: $file_path";
    }

    my $content;
    eval {
        $content = read_file($file_path, { binmode => ':utf8' });
    };
    if ($@) {
        croak "Cannot read rules file: $@";
    }

    my $config;
    eval {
        $config = decode_json($content);
    };
    if ($@) {
        croak "Invalid JSON in rules file: $@";
    }

    unless (ref $config eq 'HASH' && exists $config->{rules}) {
        croak "Rules file must contain a 'rules' array";
    }

    unless (ref $config->{rules} eq 'ARRAY') {
        croak "Rules configuration must be an array";
    }

    my $valid_rules = 0;
    for my $i (0 .. $#{$config->{rules}}) {
        my $rule = $config->{rules}[$i];

        unless (ref $rule eq 'HASH') {
            croak "Rule $i must be an object/hash";
        }

        unless (exists $rule->{name} && defined $rule->{name} && $rule->{name} ne '') {
            croak "Rule $i missing required 'name' field";
        }

        unless (exists $rule->{pattern} && defined $rule->{pattern} && $rule->{pattern} ne '') {
            croak "Rule $i missing required 'pattern' field";
        }

        eval { qr/$rule->{pattern}/ };
        if ($@) {
            croak "Rule $i has invalid regex pattern: $@";
        }

        my $enabled = exists $rule->{enabled} ? $rule->{enabled} : 1;
        $valid_rules++ if $enabled;
    }

    unless ($valid_rules) {
        croak "No valid enabled rules found in configuration";
    }

    return 1;
}

1;

__END__

=head1 RULE FORMAT

Rules are stored in JSON format with the following structure:

    {
      "rules": [
        {
          "name": "AWS Access Key",
          "pattern": "AKIA[0-9A-Z]{16}",
          "description": "AWS Access Key ID",
          "example": "AKIAIOSFODNN7EXAMPLE",
          "enabled": true
        }
      ]
    }

Required fields:
- name: Human-readable name for the rule
- pattern: Perl-compatible regular expression

Optional fields:
- description: Detailed description of what this rule detects
- example: Example of what would be caught by this rule
- enabled: Whether this rule is active (default: true)

=head1 AUTHOR

Security Engineering Team

=head1 COPYRIGHT AND LICENSE

This software is copyright (c) 2024.

=cut