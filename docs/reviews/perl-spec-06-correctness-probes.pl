use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/../../perl/lib", "$FindBin::Bin/../../perl/t/lib";
my $root = shift @ARGV // "$FindBin::Bin/../..";
use Mail::DKIM2::MessageInstance; use Mail::DKIM2::Signature; use Mail::DKIM2::Verifier; use Mail::DKIM2::Common qw(parse_mime build_signing_input); use DKIM2TestKeys; use MIME::Base64 qw(encode_base64);
my $base="From: a\@test1.dkim2.com\r\nTo: b\@test2.dkim2.com\r\nSubject: test\r\n\r\nbody\r\n";
my $mi=Mail::DKIM2::MessageInstance->calculate(parse_mime($base))->as_string;
my $key=DKIM2TestKeys::private_key('test1.dkim2.com','sel1');
sub check {
my($name,$mival,$alg,$ts,$extra)=@_; $alg //='rsa-sha256'; $ts //=time;
my $s=Mail::DKIM2::Signature->new(Sequence=>1,Version=>1,Timestamp=>$ts,Domain=>'test1.dkim2.com',MailFrom=>'a@test1.dkim2.com',RcptTo=>['b@test2.dkim2.com'],Signatures=>[['sel1',$alg,'']]);
my $in=build_signing_input(mi_headers=>[{v=>1,raw=>"Message-Instance: $mival\r\n"}],signing_i=>1,signature=>$s,signing_header=>$s->as_folded_string_without_data);
my $val=encode_base64($key->sign_message($in,'SHA256','v1.5'),''); $s->set_tag('s',"sel1:$alg:$val");
my $raw=$s->as_folded_string."\r\nMessage-Instance: $mival\r\n".$base;
my $v=Mail::DKIM2::Verifier->new(PubkeyCallback=>DKIM2TestKeys::pubkey_callback()); $v->PRINT($raw); $v->CLOSE; print "$name: ",$v->result_detail,"\n";
}
check('baseline',$mi); my $up=$mi; $up =~s/h=/H=/; check('uppercase H',$up);
check('duplicate h',"m=1; h=sha256:AAAA:AAAA; ".substr($mi,index($mi,'h=')));
check('unknown signature algorithm',$mi,'future-alg'); check('malformed timestamp',$mi,undef,'garbage');
my $upm=$mi; $upm =~s/m=/M=/; check('uppercase M',$upm);
{ package ReviewRR; sub new {bless {txt=>$_[1]},$_[0]} sub type {'TXT'} sub txtdata {$_[0]{txt}} package ReviewReply; sub new {bless {rr=>$_[1]},$_[0]} sub answer {@{$_[0]{rr}}} package ReviewResolver; sub new {bless {reply=>$_[1]},$_[0]} sub query {$_[0]{reply}} }
use JSON qw(decode_json); use Path::Tiny;
my $dns=decode_json(path("$root/perl/t/data/dns.json")->slurp); my $txt=$dns->{'test1.dkim2.com'}{'sel1._domainkey'}[0][1];
my $sig=Mail::DKIM2::Signature->new(Domain=>'test1.dkim2.com',Signatures=>[['sel1','rsa-sha256','AAAA']]);
my $r=ReviewResolver->new(ReviewReply->new([ReviewRR->new($txt),ReviewRR->new('v=DKIM1; k=rsa; p=;')])); my $v=Mail::DKIM2::Verifier->new(Resolver=>$r); my $pk=$v->fetch_public_key($sig,0); print 'two DNS TXT records: ',($pk ? 'key accepted' : 'rejected'),"\n";
my $badtxt=$txt; $badtxt =~s/k=rsa/k=unknown/; my $badkey=Mail::DKIM2::Common::parse_dkim_pubkey($badtxt); print 'unknown key algorithm: ',($badkey?'key accepted':'rejected'),"\n";
