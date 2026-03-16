use 5.20.0;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Mail::DKIM2',
    AUTHOR           => 'Bron Gondwana <brong@fastmailteam.com>',
    VERSION_FROM     => 'lib/Mail/DKIM2/Common.pm',
    ABSTRACT         => 'DKIM2 signing and verification for email',
    LICENSE          => 'perl_5',
    MIN_PERL_VERSION => '5.20.0',

    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => '0',
    },

    BUILD_REQUIRES => {
        'Test::More'  => '0.96',
    },

    PREREQ_PM => {
        'Algorithm::Diff'                        => '0',
        'Carp'                                   => '0',
        'CryptX'                                 => '0.060',
        'Email::MIME'                            => '0',
        'Exporter'                               => '0',
        'JSON::XS'                               => '0',
        'List::Util'                             => '0',
        'MIME::Base64'                           => '0',
    },

    TEST_REQUIRES => {
        'Email::MIME'  => '0',
        'JSON'         => '0',
        'Path::Tiny'   => '0',
        'Test::More'   => '0.96',
    },

    META_MERGE => {
        'meta-spec' => { version => 2 },
        resources   => {
            repository => {
                type => 'git',
                url  => 'https://github.com/dkim2wg/interop.git',
                web  => 'https://github.com/dkim2wg/interop',
            },
            bugtracker => {
                web => 'https://github.com/dkim2wg/interop/issues',
            },
        },
    },

    EXE_FILES => [
        'bin/calculate-dkim2.pl',
        'bin/calculate-mailversion.pl',
        'bin/reverse-mailversion.pl',
        'bin/validate-mailversion.pl',
        'bin/validate.pl',
        'bin/verify-sig.pl',
    ],

    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Mail-DKIM2-*' },
);
