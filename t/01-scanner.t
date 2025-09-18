#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use FindBin;
use lib "$FindBin::Bin/../lib";

use CamelLeaked::Scanner;
use CamelLeaked::Rules;

plan tests => 12;

my $test_rules_content = q{
{
  "rules": [
    {
      "name": "Test API Key",
      "pattern": "test_api_key_[0-9a-f]{32}",
      "description": "Test API key pattern",
      "enabled": true
    },
    {
      "name": "AWS Access Key",
      "pattern": "AKIA[0-9A-Z]{16}",
      "description": "AWS Access Key ID",
      "enabled": true
    }
  ]
}
};

my $rules_file = 't/test_rules.json';
open my $fh, '>', $rules_file or die "Cannot create test rules file: $!";
print $fh $test_rules_content;
close $fh;

my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
isa_ok($rules, 'CamelLeaked::Rules', 'Rules object created');

lives_ok { $rules->load_rules() } 'Rules loaded successfully';
is($rules->rule_count(), 2, 'Correct number of rules loaded');

my $scanner = CamelLeaked::Scanner->new(rules => $rules);
isa_ok($scanner, 'CamelLeaked::Scanner', 'Scanner object created');

subtest 'Basic diff scanning' => sub {
    plan tests => 3;

    my $diff_content = q{
diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -1,3 +1,4 @@
 import os
+api_key = "test_api_key_1234567890abcdef1234567890abcdef"

 def main():
};

    my @findings = $scanner->scan_diff($diff_content);
    is(scalar @findings, 1, 'One finding detected');
    is($findings[0]->{rule_name}, 'Test API Key', 'Correct rule matched');
    is($findings[0]->{file}, 'test.py', 'Correct file detected');
};

subtest 'AWS key detection' => sub {
    plan tests => 2;

    my $diff_content = q{
diff --git a/config.yaml b/config.yaml
index 1234567..abcdefg 100644
--- a/config.yaml
+++ b/config.yaml
@@ -1,2 +1,3 @@
 database:
   host: localhost
+aws_access_key: AKIAIOSFODNN7EXAMPLE
};

    my @findings = $scanner->scan_diff($diff_content);
    is(scalar @findings, 1, 'One AWS key finding detected');
    is($findings[0]->{rule_name}, 'AWS Access Key', 'AWS key rule matched');
};

subtest 'Ignore comments work' => sub {
    plan tests => 1;

    my $diff_content = q{
diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -1,3 +1,4 @@
 import os
+api_key = "test_api_key_1234567890abcdef1234567890abcdef"  # camel-leaked-ignore

 def main():
};

    my @findings = $scanner->scan_diff($diff_content);
    is(scalar @findings, 0, 'Ignored line not detected');
};

subtest 'Multiple findings in one diff' => sub {
    plan tests => 2;

    my $diff_content = q{
diff --git a/secrets.txt b/secrets.txt
index 1234567..abcdefg 100644
--- a/secrets.txt
+++ b/secrets.txt
@@ -1,4 +1,6 @@
 # Configuration file
+api_key = "test_api_key_1234567890abcdef1234567890abcdef"
 database:
   host: localhost
+  aws_key: AKIAIOSFODNN7EXAMPLE
};

    my @findings = $scanner->scan_diff($diff_content);
    is(scalar @findings, 2, 'Two findings detected');

    my @rule_names = sort map { $_->{rule_name} } @findings;
    is_deeply(\@rule_names, ['AWS Access Key', 'Test API Key'], 'Both rules matched');
};

subtest 'Entropy detection' => sub {
    plan tests => 2;

    my $scanner_entropy = CamelLeaked::Scanner->new(
        rules => $rules,
        min_entropy => 3.0,
        min_length => 20
    );

    my $diff_content = q{
diff --git a/config.py b/config.py
index 1234567..abcdefg 100644
--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
 import os
+secret = "aB3dEf7hIj9kLm2nOpQrStUvWxYz"

 def main():
};

    my @findings = $scanner_entropy->scan_diff($diff_content);
    ok(scalar @findings >= 1, 'High entropy string detected');

    my $entropy_finding = (grep { $_->{rule_name} eq 'High Entropy String' } @findings)[0];
    ok($entropy_finding, 'High entropy rule matched');
};

subtest 'Content scanning (non-diff)' => sub {
    plan tests => 2;

    my $content = q{
import os

api_key = "test_api_key_1234567890abcdef1234567890abcdef"
aws_access = "AKIAIOSFODNN7EXAMPLE"

def main():
    pass
};

    my @findings = $scanner->scan_content($content, 'test_file.py');
    is(scalar @findings, 2, 'Two findings in content scan');
    is($findings[0]->{file}, 'test_file.py', 'Filename correctly set');
};

subtest 'Empty diff handling' => sub {
    plan tests => 1;

    my @findings = $scanner->scan_diff('');
    is(scalar @findings, 0, 'Empty diff returns no findings');
};

subtest 'Line number tracking' => sub {
    plan tests => 2;

    my $diff_content = q{
diff --git a/test.py b/test.py
index 1234567..abcdefg 100644
--- a/test.py
+++ b/test.py
@@ -10,6 +10,7 @@ class MyClass:
     def __init__(self):
         self.name = "test"

+    api_key = "test_api_key_1234567890abcdef1234567890abcdef"
     def method(self):
         pass
};

    my @findings = $scanner->scan_diff($diff_content);
    is(scalar @findings, 1, 'One finding detected');
    is($findings[0]->{line_number}, 13, 'Correct line number tracked');
};

END {
    unlink $rules_file if -f $rules_file;
}

done_testing();