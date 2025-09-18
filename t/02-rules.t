#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Test::Exception;

use FindBin;
use lib "$FindBin::Bin/../lib";

use CamelLeaked::Rules;

plan tests => 15;

my $valid_rules_content = q{
{
  "rules": [
    {
      "name": "Test Rule 1",
      "pattern": "test[0-9]+",
      "description": "Test pattern",
      "enabled": true
    },
    {
      "name": "Test Rule 2",
      "pattern": "api_key_[a-f0-9]{32}",
      "description": "API key pattern",
      "example": "api_key_1234567890abcdef1234567890abcdef",
      "enabled": false
    },
    {
      "name": "Test Rule 3",
      "pattern": "secret[A-Z]+",
      "description": "Secret pattern"
    }
  ]
}
};

my $invalid_json_content = q{
{
  "rules": [
    {
      "name": "Test Rule",
      "pattern": "test",
    }
  ]
}
};

my $missing_rules_field = q{
{
  "patterns": [
    {
      "name": "Test Rule",
      "pattern": "test"
    }
  ]
}
};

my $invalid_regex_content = q{
{
  "rules": [
    {
      "name": "Bad Regex",
      "pattern": "test[",
      "enabled": true
    }
  ]
}
};

my $no_enabled_rules = q{
{
  "rules": [
    {
      "name": "Disabled Rule",
      "pattern": "test",
      "enabled": false
    }
  ]
}
};

subtest 'Valid rules loading' => sub {
    plan tests => 4;

    my $rules_file = 't/valid_rules.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $valid_rules_content;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    isa_ok($rules, 'CamelLeaked::Rules', 'Rules object created');

    lives_ok { $rules->load_rules() } 'Valid rules loaded successfully';
    is($rules->rule_count(), 2, 'Only enabled rules loaded (2 out of 3)');

    my $rule_names = [map { $_->{name} } @{$rules->get_rules()}];
    is_deeply([sort @$rule_names], ['Test Rule 1', 'Test Rule 3'], 'Correct rules loaded');

    unlink $rules_file;
};

subtest 'File not found error' => sub {
    plan tests => 1;

    my $rules = CamelLeaked::Rules->new(config_file => 'nonexistent.json');
    dies_ok { $rules->load_rules() } 'Dies when config file not found';
};

subtest 'Invalid JSON error' => sub {
    plan tests => 1;

    my $rules_file = 't/invalid_json.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $invalid_json_content;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    dies_ok { $rules->load_rules() } 'Dies on invalid JSON';

    unlink $rules_file;
};

subtest 'Missing rules field error' => sub {
    plan tests => 1;

    my $rules_file = 't/missing_rules.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $missing_rules_field;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    dies_ok { $rules->load_rules() } 'Dies when rules field missing';

    unlink $rules_file;
};

subtest 'Invalid regex error' => sub {
    plan tests => 1;

    my $rules_file = 't/invalid_regex.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $invalid_regex_content;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    dies_ok { $rules->load_rules() } 'Dies on invalid regex pattern';

    unlink $rules_file;
};

subtest 'No enabled rules error' => sub {
    plan tests => 1;

    my $rules_file = 't/no_enabled.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $no_enabled_rules;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    dies_ok { $rules->load_rules() } 'Dies when no enabled rules found';

    unlink $rules_file;
};

subtest 'Get rule by name' => sub {
    plan tests => 3;

    my $rules_file = 't/lookup_test.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $valid_rules_content;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    $rules->load_rules();

    my $rule = $rules->get_rule_by_name('Test Rule 1');
    ok($rule, 'Found existing rule');
    is($rule->{name}, 'Test Rule 1', 'Correct rule returned');

    my $missing = $rules->get_rule_by_name('Nonexistent Rule');
    is($missing, undef, 'Returns undef for missing rule');

    unlink $rules_file;
};

subtest 'Add rule at runtime' => sub {
    plan tests => 3;

    my $rules_file = 't/runtime_test.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $valid_rules_content;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    $rules->load_rules();

    my $initial_count = $rules->rule_count();

    lives_ok {
        $rules->add_rule(
            name => 'Runtime Rule',
            pattern => 'runtime[0-9]+',
            description => 'Added at runtime'
        );
    } 'Rule added successfully';

    is($rules->rule_count(), $initial_count + 1, 'Rule count increased');

    my $added_rule = $rules->get_rule_by_name('Runtime Rule');
    ok($added_rule, 'Added rule can be retrieved');

    unlink $rules_file;
};

subtest 'Add invalid rule fails' => sub {
    plan tests => 2;

    my $rules_file = 't/invalid_add_test.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $valid_rules_content;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    $rules->load_rules();

    dies_ok {
        $rules->add_rule(
            pattern => 'test[0-9]+',
        );
    } 'Dies when name missing';

    dies_ok {
        $rules->add_rule(
            name => 'Bad Rule',
            pattern => 'test[',
        );
    } 'Dies on invalid regex';

    unlink $rules_file;
};

subtest 'Validate config file static method' => sub {
    plan tests => 2;

    my $rules_file = 't/validate_test.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $valid_rules_content;
    close $fh;

    lives_ok {
        CamelLeaked::Rules->validate_config_file($rules_file);
    } 'Valid config file passes validation';

    dies_ok {
        CamelLeaked::Rules->validate_config_file('nonexistent.json');
    } 'Nonexistent file fails validation';

    unlink $rules_file;
};

subtest 'Rule pattern compilation' => sub {
    plan tests => 2;

    my $rules_file = 't/pattern_test.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $valid_rules_content;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    $rules->load_rules();

    my $rule = $rules->get_rule_by_name('Test Rule 1');
    isa_ok($rule->{pattern}, 'Regexp', 'Pattern compiled to regex object');

    my $test_string = 'test123';
    ok($test_string =~ $rule->{pattern}, 'Compiled pattern matches correctly');

    unlink $rules_file;
};

subtest 'Empty rules array' => sub {
    plan tests => 1;

    my $empty_rules = q{{"rules": []}};
    my $rules_file = 't/empty_rules.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $empty_rules;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    dies_ok { $rules->load_rules() } 'Dies on empty rules array';

    unlink $rules_file;
};

subtest 'Rule defaults' => sub {
    plan tests => 3;

    my $minimal_rule = q{
{
  "rules": [
    {
      "name": "Minimal Rule",
      "pattern": "minimal"
    }
  ]
}
};

    my $rules_file = 't/minimal_rule.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $minimal_rule;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    $rules->load_rules();

    my $rule = $rules->get_rule_by_name('Minimal Rule');
    is($rule->{description}, '', 'Default empty description');
    is($rule->{example}, '', 'Default empty example');
    is($rule->{enabled}, 1, 'Default enabled true');

    unlink $rules_file;
};

subtest 'Rule object structure' => sub {
    plan tests => 5;

    my $rules_file = 't/structure_test.json';
    open my $fh, '>', $rules_file or die "Cannot create test file: $!";
    print $fh $valid_rules_content;
    close $fh;

    my $rules = CamelLeaked::Rules->new(config_file => $rules_file);
    $rules->load_rules();

    my $rule = $rules->get_rule_by_name('Test Rule 1');
    ok(exists $rule->{name}, 'Rule has name field');
    ok(exists $rule->{pattern}, 'Rule has pattern field');
    ok(exists $rule->{description}, 'Rule has description field');
    ok(exists $rule->{example}, 'Rule has example field');
    ok(exists $rule->{enabled}, 'Rule has enabled field');

    unlink $rules_file;
};

done_testing();