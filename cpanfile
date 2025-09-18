requires 'perl', '5.024';

# Core modules for object-oriented programming
requires 'Moo', '>= 2.000000';

# JSON handling
requires 'JSON::MaybeXS', '>= 1.004000';

# File operations
requires 'File::Slurp', '>= 9999.00';

# Email functionality
requires 'Email::Stuffer', '>= 0.015';

# HTTP client for GitHub API
requires 'Mojolicious', '>= 9.00';

# Command line argument parsing
requires 'Getopt::Long', '>= 2.50';

# Documentation
requires 'Pod::Usage', '>= 2.00';

# Cryptographic randomness for entropy detection
requires 'Math::Random::Secure', '>= 0.080001';

# Base64 encoding/decoding
requires 'MIME::Base64', '>= 3.15';

# Error handling
requires 'Carp', '>= 1.50';

# Testing dependencies
on 'test' => sub {
    requires 'Test::More', '1.302190';
    requires 'Test::Exception', '0.43';
    requires 'Test::MockModule', '0.177.0';
    requires 'Test::Deep', '1.130';
};

# Development dependencies
on 'develop' => sub {
    requires 'Perl::Critic', '1.140';
    requires 'Perl::Tidy', '20230309';
    requires 'Pod::Coverage::TrustPod', '0.100006';
    requires 'Test::Pod', '1.52';
    requires 'Test::Pod::Coverage', '1.10';
    requires 'Devel::Cover', '1.38';
};