package Crypto::PaddingOracle::Encrypt;
use strict;
use warnings;
use Crypto::PaddingOracle::Decrypt;

sub new
{
    my ($self, %args) = @_;
    die "No oracle function provided" unless $args{oracle_func};    
    bless {
        #oracle_func: a code ref to a function that returns True only if there
        #is no padding error. Prototype: oracle($iv, $block, $char)
        oracle_func => $args{oracle_func},
        #blocksize: an integer value with the size of each cipher block
        blocksize  => $args{blocksize},
        #tasks: number of threads to run in parallel for each character of a
        #block. This might speed up things, but sometimes it is better to use
        #only one thread to avoid crashing the application
        tasks => $args{tasks} || 1,
        #
        decrypt => Crypto::PaddingOracle::Decrypt->new(%args),
    }, $self
}

sub set_block
{
    my ($self, $blocks, $index, $data) = @_;
    my @dec = $self->{decrypt}->get_block($blocks, $index, 0);
    if ($index == 0)
    {
        unshift @{$blocks}, "";
        $index = 1;
    }
    $blocks->[$index - 1] = join '', map {
        chr(ord(substr($data, $_, 1)) ^ $dec[$_])
    } 0 .. @dec - 1;
}

sub __rand_bytes
{
    my ($self, $count) = @_;
    join '', map { chr rand 256 } 1 .. $count;
}

sub encrypt
{
    my ($self, $plaintext) = @_;
    my $blocksize = $self->{blocksize};
    my $padding   = $blocksize - length($plaintext) % $blocksize;
    $plaintext   .= chr($padding) x $padding if $padding;
    my @blocks;
    for (my $i = length($plaintext) / $blocksize - 1; $i > -1; $i --)
    {
        unshift @blocks, $self->__rand_bytes($blocksize);
        my $data = substr($plaintext, $i * $blocksize, $blocksize);
        $self->set_block(\@blocks, 0, $data);
    }
    join '', @blocks
}

1;