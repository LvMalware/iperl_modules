package Crypto::PaddingOracle::Decrypt;
use strict;
use threads;
use warnings;
use Thread::Queue;
use threads::shared;

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
    }, $self
}

sub get_char
{
    my ($self, $iv, $block, $padding, $index, $done) = @_;
    my $queue = Thread::Queue->new(0 .. 255);
    $queue->end();
    my $found :shared;
    $found = undef;
    for my $t (1 .. $self->{tasks})
    {
        async {
            while (defined(my $char = $queue->dequeue()))
            {
                #print "[THREAD $t] Trying char $char\n";
                my $newiv = substr($iv, 0, $index) . chr($char);
                $newiv .= join '', map { chr($_ ^ $padding) } @{$done} if @{$done};
                if ($self->{oracle_func}->($newiv, $block, $char))
                {
                    lock($found);
                    $queue->dequeue($queue->pending()) if $queue->pending();
                    $found = $char ^ $padding unless $found;
                }
            }
        };
    }
    while (threads->list(threads::running) > 0) {};
    map { $_->join() } threads->list(threads::all);    
    $found
}

sub get_block
{
    my ($self, $blocks, $index, $clean) = @_;
    my $iv = $blocks->[$index - 1];
    my @done;
    for (my $i = length($iv) - 1; $i > -1; $i --)
    {
        my $padding = length($iv) - $i;
        my $char = $self->get_char(
            $iv, $blocks->[$index], $padding, $i, \@done
        );
        die "Can't decrypt block $index" unless defined($char);
        unshift @done, $char;
    }
    map { $done[$_] ^= ord(substr($iv, $_, 1)) } 0 .. @done - 1 if $clean;
    wantarray ? @done : join '', map { chr } @done;
}

sub decrypt
{
    my ($self, $ciphertext) = @_;
    my @blocks = map {
        substr($ciphertext, $_ * $self->{blocksize}, $self->{blocksize})
    } 0 .. (length($ciphertext) / $self->{blocksize} - 1);
    my @plaintext = map {
        my $dec = $self->get_block(\@blocks, $_, 1);
        $dec
    } 1 .. $#blocks;
    join '', @plaintext
}

1;
